#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script tests that a file created on one binding is immediately available when accessed
on a different binding in the environment.

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -v      Verbose
   -1      First binding id
   -2      Second binding id
EOF
}

iters=6
verbose=0
vverbose=0
b1="none"
b2="none"
pass=0
fail=0

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
         w)
             vverbose=1
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

# directory for the file
filedir=files/dual-binding-create-dir
# name of file being created
createdfile=$filedir/dual-binding-create.file

# The fibonacci sequence; if fewer than this many seconds have passed
# since last ENOENT propfind on the missing file, no propfind is generated
fibs=(0 1 2 3 5 8 13 21 34 55 89 144 233 377 610)

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

#### Set up
# Cleanup whatever might be in there
rm -f $bid1path/$filedir/*
rmdir $bid1path/$filedir

# Reset the state of the files to an initial state
if [ $verbose -eq 1 ]; then
    btool invalidate srv-bindings-$b1-files.mount
else
    btool invalidate srv-bindings-$b1-files.mount > /dev/null 2>&1
fi

# make the directory for the new file and put a seed file there
# (just to have a non-empty directory)
mkdir $bid1path/$filedir

iter=0
while [ $iter -lt $iters ]
do
    sleeptime=${fibs[$iter]}

    if [ $verbose -eq 1 ]; then
        echo "Sleeping $sleeptime seconds"
    fi
    sleep $sleeptime

    if [ $verbose -eq 1 ]; then
        echo "$iter: cat $bid1path/$createdfile"
        date '+%Y-%m-%d %H:%M:%S'
        cat $bid1path/$createdfile
    else
        # We haven't created the file yet, so access should trigger fibonacci backoff
        cat $bid1path/$createdfile > /dev/null 2>&1
    fi

    iter=$((iter + 1))
done

# Create file on binding two
# Binding one is now in fibonacci backoff for 8 seconds, create file on bid2
echo "createdfile" > $bid2path/$createdfile

# Access file on binding one; won't be found for 8 seconds
# We only increment on propfinds returning ENOENT
# We did 5 iters above, on the 5th, the backoff window gets set to 8

for iter in 1 2 3; do
    if [ $verbose -eq 1 ]; then
        echo "$iter: cat $bid1path/$createdfile should fail"
        date '+%Y-%m-%d %H:%M:%S'
    fi

    if [ $verbose -eq 1 ]; then
        cat $bid1path/$createdfile
    else
        cat $bid1path/$createdfile > /dev/null 2>&1
    fi
    # Still in fibonacci backoff window, so should fail, since this binding doesn't think the file exists
    if [ $? -eq 0 ]; then
        fail=$((fail + 1))
        echo "FAIL"
    else
        pass=$((pass + 1))
        echo "PASS"
    fi

    # Sleep to use up part of the fibonacci backoff window
    sleep 3
done

if [ $verbose -eq 1 ]; then
    echo "$iter: cat $bid1path/$createdfile should succeed"
    date '+%Y-%m-%d %H:%M:%S'
fi

# We should have slept 9 seconds and have slipped out of the fibonacci backoff window.
# Expect this access to trigger a propfind, and return success on fail access
if [ $verbose -eq 1 ]; then
    cat $bid1path/$createdfile
else
    cat $bid1path/$createdfile > /dev/null 2>&1
fi
if [ $? -ne 0 ]; then
    fail=$((fail + 1))
    echo "FAIL"
else
    pass=$((pass + 1))
    echo "PASS"
fi

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: attempts failed $fail; attempts passed $pass"
else
    echo "PASS: attempts passed $pass"
fi

