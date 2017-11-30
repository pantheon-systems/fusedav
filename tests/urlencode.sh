#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests, but it does so by adding
special characters to the filename and ensuring that they are properly
processed by the backend

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -v      Verbose
EOF
}

iters=0
verbose=0
while getopts "hi:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
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

if [ $iters -eq 0 ]; then
    iters=1
fi

pass=0
fail=0

compare() {
    # If the first file is zero-size, we fail
    # else use cmp to see if files are identical
    if [ ! -s $1 ]; then
        fail=$((fail + 1))
        if [ $verbose -eq 1 ]; then
            echo "Failed on compare: $1 has size 0"
        fi
    else
        if [ $verbose -eq 1 ]; then
            echo "cmp -s $1 $2"
        fi
        cmp -s $1 $2
        if [ $? -eq 0 ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            if [ $verbose -eq 1 ]; then
                echo "Failed on compare: $1 $2"
            fi
        fi
    fi
}

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# append; this also creates a file for later tests
rm urlencode.file > /dev/null 2>&1
rm urlencode.file.save > /dev/null 2>&1
head -c 64 /dev/urandom > urlencode.file
cp urlencode.file urlencode.file.save

for urlencodedchar in \# \+ \, \: \= @ \[ \]
do

    # mv; move all files from original to url-encoded name
    iter=1
    while [ $iter -le $iters ]
    do
        if [ $verbose -eq 1 ]; then
            echo "$iter: mv urlencode.file urlencode-$urlencodedchar.file-$iter"
        fi
        mv urlencode.file urlencode-$urlencodedchar.file-$iter
        # sleep long enough to let the file expire from the cache, else we don't
        # even go to the server and do a GET
        sleep 15
        compare urlencode-$urlencodedchar.file-$iter urlencode.file.save
        # get the original back for next round
        cp urlencode.file.save urlencode.file
        iter=$((iter + 1))
    done
    
    # mv; move all files from cp test back to original
    iter=1
    while [ $iter -le $iters ]
    do
        if [ $verbose -eq 1 ]; then
            echo "$iter: mv urlencode-$urlencodedchar.file-$iter urlencode.file"
        fi
        mv urlencode-$urlencodedchar.file-$iter urlencode.file
        compare urlencode.file urlencode.file.save
        iter=$((iter + 1))
    done
    
    # cp files
    iter=1
    while [ $iter -le $iters ]
    do
        if [ $verbose -eq 1 ]; then
            echo "$iter: cp urlencode.file urlencode-$urlencodedchar.file-$iter"
        fi
        cp urlencode.file urlencode-$urlencodedchar.file-$iter
        compare urlencode.file urlencode-$urlencodedchar.file-$iter
        iter=$((iter + 1))
    done
    
    # rm files
    iter=1
    while [ $iter -le $iters ]
    do
        if [ $verbose -eq 1 ]; then
            echo "$iter: rm urlencode-$urlencodedchar.file-$iter"
        fi
        rm urlencode-$urlencodedchar.file-$iter
        if [ -f urlencode-$urlencodedchar.file-$iter ]; then
            fail=$((fail + 1))
            if [ $verbose -eq 1 ]; then
                echo "Failed on rm: urlencode-$urlencodedchar.file-$iter"
            fi
        else
            pass=$((pass + 1))
        fi
        iter=$((iter + 1))
    done
done

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: files failed $fail; files passed $pass"
else
    echo "PASS: files passed $pass"
fi


