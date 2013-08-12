#! /bin/bash
# tolerate errors
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

# do 64 rounds by default
iters=64
verbose=0
# assuming we are using base fusedav; but allow for override
fusedavdir="fusedav"
while getopts "hi:d:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
             ;;
         d)
             fusedavdir=$OPTARG
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

# make sure we are in the 'files' directory
# then put the output file pprof.out one directory up from files in the bindingid directory
curdir=$(pwd)
bname=$(basename $curdir)
if [ $bname != 'files' ]; then
    echo "Expected base directory to be called files"
fi
bindingdir=$(dirname $curdir)
    
pprof_out=$bindingdir/pprof.out
rm -f $pprof_out
iter=0
while [ $iter -le $iters ]
do
    # get the pid
    pid=$(ps aux | grep mount.$fusedavdir | grep -v grep | sort -nrk 6 | awk '{printf "%5d\n", $2}')
    
    # get the current memory use
    res=$(ps aux | grep mount.$fusedavdir | grep -v grep | sort -nrk 6 | awk '{printf "%5d %d\n", $2, $6}')
    echo "$iter: before make: $res"
    echo "$iter: before make: $res" >> $pprof_out
    
    echo "$iter: make -f /opt/$fusedavdir/tests/Makefile testdir=/opt/$fusedavdir/tests"
    echo "$iter: make -f /opt/$fusedavdir/tests/Makefile testdir=/opt/$fusedavdir/tests" >> $pprof_out
    
    # run the tests
    make -f /opt/$fusedavdir/tests/Makefile testdir=/opt/$fusedavdir/tests

    # get the most recent heap to use as base to pprof
    prevheap=$(ls -Art /var/tmp/*.heap | tail -n 1)

    # Send our mallctl signal to fusedav; this will dump a jemalloc heap file
    echo "kill -SIGUSR2 $pid"
    kill -SIGUSR2 $pid
    
    # get the heap file just created by the SIGUSR2
    newheap=$(ls -Art /var/tmp/*.heap | tail -n 1)
    
    # do a pprof comparison between latest and previous heap filees
    echo "pprof --text --lines --inuse_space --base=$prevheap /opt/$fusedavdir/src/fusedav $newheap >> $pprof_out 2>&1"
    pprof --text --lines --inuse_space --base=$prevheap /opt/$fusedavdir/src/fusedav $newheap >> $pprof_out 2>&1
    
    res=$(ps aux | grep mount.$fusedavdir | grep -v grep | sort -nrk 6 | awk '{printf "%5d %d\n", $2, $6}')
    echo "$iter: after make: $res"
    
    # leave some time for things to settle out before next round
    sleep 60
    iter=$((iter + 1))
done

