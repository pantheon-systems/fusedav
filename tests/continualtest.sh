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
   -d      Directory name (default is fusedav)
   -p      pid of fusedav instance
   -b      bid of fusedav instance (7 chars only)
   -v      Verbose
EOF
}

# do 64 rounds by default
pid=0
bid=""
iters=64
verbose=0
# assuming we are using base fusedav; but allow for override
fusedavdir="fusedav"
while getopts "hi:d:p:b:v" OPTION
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
         p)
             pid=$OPTARG
             ;;
         b)
             bid=${OPTARG:0:6}
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
    
if [ $bid == "" ]; then
	echo "Requires bid (7 chars only)"
    exit 1
fi
    
pprof_out=$bindingdir/pprof.out
rm -f $pprof_out
iter=0
while [ $iter -le $iters ]
do
    # get the current memory use
    fusedavres=$(ps aux | grep mount.$fusedavdir | grep -v grep | grep $pid | awk '{printf "%5d %d\n", $2, $6}')
    nginxres=$(ps aux | grep nginx | grep -v grep | grep $bid | awk '{printf "%5d %d\n", $2, $6}')
    phpfmpres=$(ps aux | grep php-fpm | grep -v grep | grep $bid | awk '{printf "%5d %d\n", $2, $6}')
    echo "$(date)"
    echo "$iter: fusedav before make: $fusedavres"
    echo "$iter: fusedav before make: $fusedavres" >> $pprof_out
    echo "$iter: nginx before make: $nginxres"
    echo "$iter: nginx before make: $nginxres" >> $pprof_out
    echo "$iter: php-fpm before make: $phpfpmres"
    echo "$iter: php-fpm  before make: $phpfpmres" >> $pprof_out
    
    echo "$iter: make -f /opt/$fusedavdir/tests/Makefile run-continual-tests testdir=/opt/$fusedavdir/tests"
    echo "$iter: make -f /opt/$fusedavdir/tests/Makefile run-continual-tests testdir=/opt/$fusedavdir/tests" >> $pprof_out
    
    # run the tests
    make -f /opt/$fusedavdir/tests/Makefile run-continual-tests testdir=/opt/$fusedavdir/tests

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
        echo "pprof --text --lines --inuse_space --base=$prevheap /opt/$fusedavdir/src/fusedav $newheap >> $pprof_out 2>&1"
        pprof --text --lines --inuse_space --base=$prevheap /opt/$fusedavdir/src/fusedav $newheap >> $pprof_out 2>&1
    fi
    
    res=$(ps aux | grep mount.$fusedavdir | grep -v grep | grep $pid | awk '{printf "%5d %d\n", $2, $6}')
    echo "$iter: after make: $res"
    
    # leave some time for things to settle out before next round
    # no, dont sleep 60
    iter=$((iter + 1))
done

