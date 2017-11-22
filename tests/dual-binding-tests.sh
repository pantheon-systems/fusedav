#! /bin/bash
set +e

# This is a wrapper script. It calls dual-binding-test.sh for a variety of tests which can
# test how one binding should respond when a different binding sees a particular request.

usage()
{
cat << EOF
usage: $0 options

This script runs a series of dual binding tests

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -d      Test directory
   -v      Verbose
EOF
}

iters=0
verbose=0
testdir=/root/pantheon/fusedav/tests/
bid1=0
bid2=0

while getopts "hi:d:1:2:v" OPTION
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
             testdir=$OPTARG
             ;;
         1)
             bid1=$OPTARG
             ;;
         2)
             bid2=$OPTARG
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

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# Just list the tests to be run
# basic ops are:
# list: ls -al
# listR: ls -alR
# makedir: mkdir
# writefile: head -c 67; also give it a number of iters to write many files
# readfile: cat
# removefiles: rm -f
# removedir: rmdir
# Each of the commands has an 'f' version, e.g. flist
# The 'f' version expects failure, so failure is counted as pass

echo "ENTER dual-binding-tests"

iter=1
while [ $iter -le $iters ]
do
    echo; echo "TEST 1"; echo
    echo; echo "PRELIMINARY"; echo

    # Preliminary: remove files and dir to set a clean slate
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -c "-i 1 -c removefiles;removedir" -d "-c null"

    # On the first binding, make a directory, put some files in it, 
    # remove the files, then remove directory via the second binding
    echo; echo "TEST"; echo

    # Run the real test
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -v -c "-v -i 1 -c sleep;makedir;writefile;removefiles" -d "-v -c removedir"

    ret=$?
    if [ $ret -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

#########################################################################
    echo; echo "TEST 2"; echo
    echo; echo "PRELIMINARY"; echo

    # remove files and dir to set a clean slate
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -c "-i 1 -c removefiles;removedir" -d "-c null"

    # Add removefiles and removedir afterward, to clean up
    echo; echo "TEST"; echo

    # On the first binding, make a directory, and put some files in it, then 
    # remove directory via the second binding, which should fail (use the 'f' version to pass on failure)
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -v -c "-v -i 1 -c sleep;makedir;writefile" -d "-v -c fremovedir;removefiles;removedir"
    ret=$?
    if [ $ret -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    iter=$((iter + 1))

#########################################################################
    echo; echo "TEST 3"; echo
    echo; echo "PRELIMINARY"; echo

    # remove files and dir to set a clean slate
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -c "-i 1 -c removefiles;removedir" -d "-c null"

    # Add removefiles and removedir afterward, to clean up
    echo; echo "TEST"; echo

    # On the first binding, make a directory, and put some files in it, then 
    # ls the binding, then remove some files but leave others, then ls the binding
    # and expect to get back only the files which weren't removed
    $testdir/dual-binding-test.sh -1 $bid1 -2 $bid2 -a basic-ops.sh -b basic-ops.sh -v -c "-v -i 2 -c sleep;makedir;writefile" -d "-v -c list;removefile;list;removefiles;removedir"
    echo "Check the two lists; one should be missing basic-ops-file-1"
    ret=$?
    if [ $ret -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi

    iter=$((iter + 1))

#########################################################################


done

#########################################################################
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
