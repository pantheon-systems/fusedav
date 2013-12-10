#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

OPTIONS:
   -h      Show this message
   -b      second binding
   -v      Verbose
EOF
}

binding="none"
iters=64
verbose=0
while getopts "hi:b:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
             ;;
         b)
             binding=$OPTARG
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

if [ $binding == "none" ]; then
    echo "Test cannot be run without a second binding. Aborting ..."
    exit
fi

pass=0
fail=0

createdelete() {
    mkdir -p a/b/c/d/e/
    touch a/b/c/d/e/f.txt
    rm -f ../../$binding/files/a/b/c/d/e/f.txt
    sleep 4
    result=$( { ls a/b/c/d/e/f.txt; } 2>&1 )
    # 1 means grep didn't find No such file or directory, but it should have, so fail
    echo $result | grep -q "No such file or directory"
    if [ $? -eq 1 ]; then
        fail=$(( fail + 1 ))
        if [ $verbose -eq 1 ]; then
            echo "fail: $result"
        fi
    else
        pass=$(( pass + 1 ))
        if [ $verbose -eq 1 ]; then
            echo "pass: $result"
        fi
    fi
}

# make sure we are in the 'files' directory
curdir=$(pwd)
bname=$(basename $curdir)
if [ $bname != 'files' ]; then
    echo "Expected base directory to be called files"
    exit
fi

rm -rf a

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# cp files
iter=1

while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo
        echo "$iter: touch-rm-ls"
    fi
    createdelete
    # sleep 4
    iter=$((iter + 1))
done

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: $fail"
else
    echo "PASS: $pass"
fi


