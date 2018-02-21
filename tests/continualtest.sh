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
   -t      Directory name (default is /opt/fusedav/tests)
   -b      Binary name (default is /opt/fusedav/src/fusedav)
   -p      pid of fusedav instance
   -v      Verbose
EOF
}

# do 64 rounds by default
pid=0
iters=64
verbose=0
# assuming we are using base fusedav; but allow for override
fusedavtestdir="/opt/fusedav/tests"
fusedavbinary="/opt/fusedav/src/fusedav"
while getopts "hi:t:b:p:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
             ;;
         t)
             fusedavtestdir=$OPTARG
             ;;
         b)
             fusedavbinary=$OPTARG
             ;;
         p)
             pid=$OPTARG
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

if [ $pid -eq 0 ]; then
    echo "Requires pid"
    exit 1
fi
    
pprof_out=$bindingdir/pprof.out
rm -f $pprof_out
iter=0
while [ $iter -le $iters ]
do
    # get the current memory use
    res=$(ps aux | grep valhalla | grep -v grep | grep $pid | awk '{printf "%5d %d\n", $2, $6}')
    echo "$iter: before make: $res"
    echo "$iter: before make: $res" >> $pprof_out
    
    echo "$iter: make -f $fusedavtestdir/Makefile run-continual-tests testdir=$fusedavtestdir"
    echo "$iter: make -f $fusedavtestdir/Makefile run-continual-tests testdir=$fusedavtestdir" >> $pprof_out
    
    # run the tests
    make -f $fusedavtestdir/Makefile run-continual-tests testdir=$fusedavtestdir

    if [ $iter -gt 0 ]; then
        # get the most recent heap to use as base to pprof
        prevheap=$(ls -Art /var/tmp/*${pid}*.heap | tail -n 1)
    fi

    # Send our mallctl signal to fusedav; this will dump a jemalloc heap file
    echo "kill -SIGUSR2 $pid"
    kill -SIGUSR2 $pid
    
    # get the heap file just created by the SIGUSR2
    newheap=$(ls -Art /var/tmp/*${pid}*.heap | tail -n 1)
    
    if [ $iter -gt 0 ]; then
        # do a pprof comparison between latest and previous heap filees
        echo "pprof --text --lines --inuse_space --base=$prevheap $fusedavbinary $newheap >> $pprof_out 2>&1"
        pprof --text --lines --inuse_space --base=$prevheap $fusedavbinary $newheap >> $pprof_out 2>&1
    fi
    
    res=$(ps aux | grep valhalla | grep -v grep | grep $pid | awk '{printf "%5d %d\n", $2, $6}')
    echo "$iter: after make: $res"
    
    # leave some time for things to settle out before next round
    # no, dont sleep 60
    iter=$((iter + 1))
done

