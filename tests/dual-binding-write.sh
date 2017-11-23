#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script enables dual-binding tests

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -v      Verbose
   -1      First binding id
   -2      Second binding id
EOF
}

iters=16
doubleiters=32
verbose=0
b1="none"
b2="none"

echo "ENTER dual-binding-write"

while getopts "hi:1:2:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
             ;;
         1)
             b1=$OPTARG
             ;;
         2)
             b2=$OPTARG
             ;;
         v)
             verbose=1
             ;;
         ?)
             usage
             exit
             ;;
     esac
done

if [ $b1 == "none" ]; then
    echo "Binding 1 id is required. Exiting ..."
    exit
fi

if [ $b2 == "none" ]; then
    echo "Binding 2 id is required. Exiting ..."
    exit
fi

bid1path=/srv/bindings/$b1
bid2path=/srv/bindings/$b2
filedir=dual-binding-dir

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

repeated_ls(){
    while true; do
        if [ $verbose -eq 1 ]; then
            echo "ls $1"
	fi
        ls $1
        sleep 1
    done
}

#### Set up
# Cleanup whatever might be in there
rm -f $bid1path/files/$filedir/*
rmdir $bid1path/files/$filedir

# make the directory for the new file and put a seed file there
# (just to have a non-empty directory)
mkdir $bid1path/files/$filedir
echo "seedfile" > $bid1path/files/$filedir/seedfile.txt
# Keep accessing the directory on bid1 to trigger the
# 2-second propfind window which should no longer exist
repeated_ls $bid1path/files/$filedir &
# Save of the function pid to kill it later
lspid=$!

iter=0
# Write several new files to bid2 and expect them to appear on bid1 without delay 
while [ $iter -lt $doubleiters ]; do
    head -c 67 /dev/urandom > $bid2path/files/$filedir/file-$iter.txt
    cat $bid1path/files/$filedir/file-$iter.txt > /dev/null 2>&1

    if [ $? -eq 0 ]; then
	pass=$((pass + 1))
        if [ $verbose -eq 1 ]; then
	    echo "iter $iter: pass"
	fi
    else
	fail=$((fail + 1))
        if [ $verbose -eq 1 ]; then
	    echo "iter $iter: fail"
	fi
    fi

    # Sleep from 0 - iter seconds the first half,
    # then just 1 second each time the second half
    # Just testing that the sleep interval does not
    # matter for the ability to pick up the new file
    if [ $iter -lt $iters ]; then
        sleep $iter 
    else
	sleep 1
    fi

    iter=$((iter + 1))
done

kill $lspid

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: tests failed $fail; files passed $pass"
else
    echo "PASS: tests passed $pass"
fi

