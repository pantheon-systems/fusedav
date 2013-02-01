#! /bin/bash

start=1
# Skip to test $start, which can be passed as a parameter
if [ $# -gt 0 ]
then
    start=$1
fi

starttime=$(date +%s)

    iters=1
    jters=1
    # append; this also creates a file for later tests
    test=1
    rm -f cltest2.file > /dev/null 2>&1
    rm -f cltest2.file-* > /dev/null 2>&1
    touch cltest2.file
    if [ $start -le $test ]; then
        while [ $iters -le 1024 ]
        do
            echo "echo $iters:'abcdefghijklmnopqrstuvwxyz' >> cltest2.file"
            echo "abcdefghijklmnopqrstuvwxyz" >> cltest2.file
            iters=$((iters + 1))
        done
    fi

for iter in {1..8192}
do
    # cp; create 10000 files
    test=2
    iters=1
    if [ $start -le $test ]; then
        while [ $iters -le $jters ]
        do
            echo "$iter: cp cltest2.file cltest2.file-$iter"
            cp cltest2.file cltest2.file-$iter
            iters=$((iters + 1))
        done
    fi

    # mv; move all files from cp test back to original
    test=3
    iters=1
    if [ $start -le $test ]; then
        while [ $iters -le $jters ]
        do
            echo "$iter: mv cltest2.file-$iter cltest2.file"
            mv cltest2.file-$iter cltest2.file
            iters=$((iters + 1))
        done
    fi

    # cp; create 10000 files
    test=4
    iters=1
    if [ $start -le $test ]; then
        while [ $iters -le $jters ]
        do
            echo "$iter: cp cltest2.file cltest2.file-$iter"
            cp cltest2.file cltest2.file-$iter
            iters=$((iters + 1))
        done
    fi

    # rm; create 10000 files
    test=5
    iters=1
    if [ $start -le $test ]; then
        while [ $iters -le $jters ]
        do
            echo "$iter: rm cltest2.file-$iter"
            rm cltest2.file-$iter
            iters=$((iters + 1))
        done
    fi
done

endtime=$(date +%s)

elapsedtime=$(( $endtime - $starttime ))

echo "Elapsed time: $elapsedtime"

