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
   -a      First program
   -b      Second program
   -c      First program command line args
   -d      Second program command line args
   Example: /root/pantheon/fusedav/tests/dual-binding-tests.sh -1 32fffe7694044da1be9c41cfd489185d -2 975b26cec42a4c1aa7976ad941aa54f9 -a basic-ops.sh -b basic-ops.sh -v -c "-v -c write" -d "-v -c read"
EOF
}

iters=0
verbose=0
b1="none"
b2="none"
pa="none"
pb="none"
ca="none"
cb="none"

echo "ENTER dual-binding-test"

scriptdir=/root/pantheon/fusedav/tests

while getopts "hi:1:2:a:b:c:d:v" OPTION
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
         a)
             pa=$OPTARG
             ;;
         b)
             pb=$OPTARG
             ;;
         c)
             ca=$OPTARG
             ;;
         d)
             cb=$OPTARG
             ;;
         s)
             scriptdir=$OPTARG
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

if [ $pa == "none" ]; then
    echo "Program a is required. Exiting ..."
    exit
fi

if [ $pb == "none" ]; then
    echo "Program b is required. Exiting ..."
    exit
fi

pa=$scriptdir/$pa
pb=$scriptdir/$pb

if [ $iters -eq 0 ]; then
    iters=1
fi

bid1dir=/srv/bindings/$b1/files
bid2dir=/srv/bindings/$b2/files

pass=0
fail=0

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
    echo "Program a on binding 1: $pa -b $bid1dir $ca"
    echo "Program b on binding 2: $pb -b $bid2dir $cb"
    echo "Script dir is $scriptdir"
fi

iter=1
while [ $iter -le $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: "
    fi
    $pa -b $bid1dir $ca
    if [ $? -eq 0 ]; then
	pass=$((pass + 1))
    else
	fail=$((fail + 1))
    fi
    $pb -b $bid2dir $cb
    iter=$((iter + 1))
done

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

echo "EXIT dual-binding-tests"
exit $fail

