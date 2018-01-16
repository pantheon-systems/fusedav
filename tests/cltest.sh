#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

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
    iters=64
fi

pass=0
fail=0

compare() {
    # If the first file is zero-size, we fail
    # else use cmp to see if files are identical
    if [ ! -s $1 ]; then
        fail=$((fail + 1))
    else
        cmp -s $1 $2
        if [ $? -eq 0 ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
        fi
    fi
}

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

echo "Current directory: $(pwd)"
# append; this also creates a file for later tests
rm cltest.file > /dev/null 2>&1
rm cltest.file.save > /dev/null 2>&1
head -c 64 /dev/urandom > cltest.file
cp cltest.file cltest.file.save

# cp files
iter=1
while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: cp cltest.file cltest.file-$iter"
    fi
    cp cltest.file cltest.file-$iter
    compare cltest.file cltest.file-$iter
    iter=$((iter + 1))
done

# mv; move all files from cp test back to original
iter=1
while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: mv cltest.file-$iter cltest.file"
    fi
    mv cltest.file-$iter cltest.file
    compare cltest.file cltest.file.save
    iter=$((iter + 1))
done

# cp files
iter=1
while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: cp cltest.file cltest.file-$iter"
    fi
    cp cltest.file cltest.file-$iter
    compare cltest.file cltest.file-$iter
    iter=$((iter + 1))
done

# rm files
iter=1
while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: rm cltest.file-$iter"
    fi
    rm cltest.file-$iter
    if [ -f cltest.file-$iter ]; then
        fail=$((fail + 1))
    else
        pass=$((pass + 1))
    fi
    iter=$((iter + 1))
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


