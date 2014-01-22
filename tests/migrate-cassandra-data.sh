#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script creates an sstable of all files in cassandra for a given site environment

OPTIONS:
   -h      Show this message
   -s      site id
   -e      site environment
   -b      bin directory, default /opt/fusedav/tests, to find required scripts
   -j      source/destination directory for the json files and new sstable files
   -k      extract files for key to json dir (-j)
   -c      convert json files to sstable files
   -l      load sstable files into Cassandra
   -v      Verbose
   -q      Quiet

   At least one of -k, -c, or -l is required
   -j is required. \'valhalla/volumes\' will be appended
   -s and -e are required for -k

   Example for extract key (-k)
   sudo /opt/fusedav/tests/migrate-cassandra-data.sh -s "d298018a-b8df-4dfc-a842-0aa507463c59" -e "dev" -j /tmp/cassandra -k

   Example for convert (-c)
   
EOF
}

# trap so that ^C won't cause the program to exit
#sstable2json hangs on error, so ^C is a way to let it carry on
trap "echo TRAP" SIGINT SIGTERM

verbose=0
quiet=0
error=0
siteid="none"
siteenv="none"
# defaults to fusedav
bindir=/opt/fusedav/tests
jsondir="none"
dbdir="none"
extractkey=0
convert=0
load=0

while getopts "hs:e:b:j:d:klcvq" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         s)
             siteid=$OPTARG
             ;;
         e)
             siteenv=$OPTARG
             ;;
         b)
             bindir=$OPTARG
             ;;
         j)
             jsondir=$OPTARG
             ;;
         d)
             dbdir=$OPTARG
             ;;
         k)
             extractkey=1
             ;;
         l)
             load=1
             ;;
         c)
             convert=1
             ;;
         v)
             verbose=1
             ;;
         q)
             quiet=1
             ;;
         ?)
             usage
             exit
             ;;
     esac
done

if [ $extractkey -eq 0 ] && [ $load -eq 0 ] && [ $convert -eq 0 ]; then
    echo "Requires at least one of -x (extractkey), -l (load), -c (convert)"
    error=1
fi

if [ $extractkey -ne 0 ]; then
    if [ $siteid == "none" ]; then
        echo "extractkey requires -s <siteid>"
        error=1
    fi
    
    if [ $siteenv == "none" ]; then
        echo "extractkey requires -e <siteenv e.g. dev, test, or live>"
        error=1
    fi
    
    if [ $dbdir == "none" ]; then
        echo "Requires -d <dbdir> which is the location of the db files to be processed"
        error=1
    else
        dbdir=${dbdir}/valhalla/volumes
    fi
fi

if [ $jsondir == "none" ]; then
    echo "Requires -j <jsondir> for a place to put and/or find the json files; \'valhalla/volumes\' will be added"
    error=1
else
    jsondir=${jsondir}/valhalla/volumes
    mkdir -p $jsondir
    if [ $verbose -ne 0 ]; then
        echo "mkdir $jsondir"
    fi
fi

if [ $error -eq 1 ]; then
    echo "Exiting ..."
    exit
fi

# Get hex key from siteid!siteenv for sstable2json
function calculate_hexkey() {
    siteid=$1
    siteenv=$2
    
    key="$siteid!$siteenv"
    if [ $verbose -ne 0 ]; then
        echo "calculate_hexkey: KEY: $key"
    fi

    # calls python script which is one of ours
    hexkey=$($bindir/cassandra-key2hex.py $key)
    if [ $verbose -ne 0 ]; then
        echo "calculate_hexkey: $hexkey"
        echo > /dev/null
    fi

    # send hexkey as return value
    echo $hexkey
}

# call cassandra's sstable2json
function do_sstable2json() {
    # file is the sstable (Data*.db) at /var/lib/cassandra/data/valhalla/volumes
    file=$1
    hexkey=$2
    bfile=$(basename $file)

    if [ $verbose -ne 0 ]; then
        echo "do_sstable2json: $file : $hexkey"
    fi
    
    jsonout=$(/bin/sstable2json $file -k $hexkey 2> $jsondir/${bfile}.error)
    echo $jsonout
}

# call cassandra's json2sstable
function do_json2sstable() {
    file=$1
    # Get the basename, but also remove the .json.
    # The json file was created by appending .json to the .db file name
    # so removing it will give the correct sstablefile below
    filebase=$(basename $file .json)
    jsonfile=$jsondir/${filebase}.json
    sstablefile=$jsondir/$filebase

    if [ $verbose -ne 0 ]; then
        echo "do_json2sstable: $file"
    fi

    if [ $quiet -eq 0 ]; then
        echo "$filebase"
    fi
    
    jsonout=$(/bin/json2sstable -K valhalla -c volumes $jsonfile $sstablefile 2> ${file}.error)
    echo $jsonout
}

# create json from sstable
function extractkey() {
    if [ $verbose -ne 0 ]; then
        echo "extractkey: siteid: $siteid siteenv: $siteenv"
    fi

    # Get the hex value from the string id
    hexkey=$(calculate_hexkey $siteid $siteenv)
    
    if [ $verbose -ne 0 ]; then
        echo "extractkey: hexkey = $hexkey"
    fi

    # in case jsondir points accidentally to /var/lib/cassandra/data/valhalla/volumes/
    # I don't want to programatically delete the .db files
    for file in $jsondir/*.json; do
        if [ -f $file ]; then
            echo "Remove .json and .db files in $jsondir and re-execute"
            echo "Exiting..."
            exit
        fi
    done
        
    # Use dbdir for location of db files
    # Process each Data db file
    for file in $dbdir/*Data*db; do
        if [ -f $file ]; then
            if [ $verbose -ne 0 ]; then
                echo "extractkey: $file : $hexkey"
            fi
            
            if [ $quiet -eq 0 ]; then
                filebase=$(basename $file)
                echo "$filebase"
            fi
        
            jsonout=$(do_sstable2json $file $hexkey)
            echo $jsonout | grep -q "\"key\":"
        
            # If this has legitimate content ("key":), send it to a file
            if [ $? -eq 0 ]; then
                filebase=$(basename $file)
                echo $jsonout > $jsondir/${filebase}.json
            fi
        fi
    done
}

# convert json to sstable
function convert() {
    # Process each json file
    for file in $jsondir/*.json; do
        if [ -f $file ]; then
            if [ $verbose -ne 0 ]; then
                echo "convert: $file"
            fi
        fi
        
        do_json2sstable $file
    done
}

function load() {
    # Load the new sstables
    # FIX ME! I think we need something other than localhost when moving between clusters
    /bin/sstableloader -d localhost $jsondir
}

if [ $extractkey -ne 0 ]; then
    if [ $quiet -eq 0 ]; then
        echo "extractkey"
    fi
    extractkey
fi

if [ $convert -ne 0 ]; then
    if [ $quiet -eq 0 ]; then
        echo "convert"
    fi
    convert
fi

if [ $load -ne 0 ]; then
    if [ $quiet -eq 0 ]; then
        echo "load"
    fi
    load
fi


