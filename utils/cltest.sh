#! /bin/bash

start=1
# Skip to test $start, which can be passed as a parameter
if [ $# -gt 0 ]
then
    start=$1
fi

starttime=$(date +%s)

for iters in 1 2 4 8 64 256 1024 16184
do

echo "JB $iters"
    # append; this also creates a file for later tests
    test=1
    rm cltest.file > /dev/null 2>&1
    touch cltest.file
    if [ $start -le $test ]; then
        iter=1
        while [ $iter -le $iters ]
        do
            echo "echo $iter:'abcdefghijklmnopqrstuvwxyz' >> cltest.file"
            echo "abcdefghijklmnopqrstuvwxyz" >> cltest.file
            iter=$((iter + 1))
        done
    fi

    # cp; create 10000 files
    test=2
    if [ $start -le $test ]; then
        iter=1
        while [ $iter -le $iters ]
        do
            echo "$iter: cp cltest.file cltest.file-$iter"
            cp cltest.file cltest.file-$iter
            iter=$((iter + 1))
        done
    fi

    # mv; move all files from cp test back to original
    test=3
    if [ $start -le $test ]; then
        iter=1
        while [ $iter -le $iters ]
        do
            echo "$iter: mv cltest.file-$iter cltest.file"
            mv cltest.file-$iter cltest.file
            iter=$((iter + 1))
        done
    fi

    # cp; create 10000 files
    test=4
    if [ $start -le $test ]; then
        iter=1
        while [ $iter -le $iters ]
        do
            echo "$iter: cp cltest.file cltest.file-$iter"
            cp cltest.file cltest.file-$iter
            iter=$((iter + 1))
        done
    fi

    # rm; create 10000 files
    test=5
    if [ $start -le $test ]; then
        iter=1
        while [ $iter -le $iters ]
        do
            echo "$iter: rm cltest.file-$iter"
            rm cltest.file-$iter
            iter=$((iter + 1))
        done
    fi
done

endtime=$(date +%s)

elapsedtime=$(( $endtime - $starttime ))

echo "Elapsed time: $elapsedtime"

