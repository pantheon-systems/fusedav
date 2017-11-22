#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script tests that non-existent files using a fibonacci backoff
properly suppress or allow a propfind. This first test accesses files in less time than
the fibonacci backoff value, so that no propfinds are generated. The second test
waits for the required fibonacci backoff to have passed, so that propfinds
are generated.

This script calls journalctl to get log messages, and uses their content
to ascertain success or failure. The log entries required are those
which don't print under production configuration. So the binding they
are run on requires that verbose logging be enabled. One way to do this
is to modify fusedav.conf to contain the following values:

log_level=6
log_level_by_section=600070707000000000700007

OPTIONS:
   -h      Show this message
   -v      Verbose
   -n      Number of iterations. Default 5 makes test take about a minute.
EOF
}

numattempts=6
verbose=0

while getopts "hvn:" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
	 n)
             numattempts=$OPTARG
             ;;
         v)
             verbose=1
             ;;
         ?)
             usage
             exit 1
             ;;
     esac
done

# Most tests need to be in the files directory, but this one needs to be
# one up.
if [ -f ../fusedav.conf ]; then
	cd ..
fi

if [ ! -f fusedav.conf ]; then
    echo "ERROR: Need to be in /srv/bindings/<bid> directory"
    exit
fi

# e.g. /srv/bindings/<bid>
path=$(pwd)
# binding id
bid=${path##*/}
# output file for journalctl, from which are read results
outfile=/tmp/propfind-negative-entry-backoff.out
# name of non-existent file
missingfile=files/basic-ops/missing-file.file
# We could use ${<file>##/} notation, but that would likely complicate it
basemissingfile=missing-file.file

# The fibonacci sequence; if fewer than this many seconds have passed
# since last ENOENT propfind on the missing file, no propfind is generated
fibs=(0 1 2 3 5 8 13 21 34 55 89 144 233 377 610)

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

numattempt=0

pass=0
fail=0


##### TEST 1
# Access a missing file on propfind fibonacci boundaries. Expect that
# each access will cause a new propfind

# For journalctl
since=$(date '+%Y-%m-%d %H:%M:%S')

# Reset the state of the 'missing file' to first attempt.
btool invalidate srv-bindings-$bid-files.mount

while [ $numattempt -lt $numattempts ]
do
    if [ $verbose -eq 1 ]; then
        echo "$numattempt: cat $missingfile"
        date '+%Y-%m-%d %H:%M:%S'
    fi

    sleeptime=${fibs[$numattempt]}

    if [ $verbose -eq 1 ]; then
	    echo "Sleeping $sleeptime seconds"
    fi
    sleep $sleeptime

    cat $missingfile

    numattempt=$(( numattempt + 1 ))
done

echo "journalctl -a -u srv-bindings-$bid-files.mount --since $since --no-pager > $outfile"
journalctl -a -u srv-bindings-$bid-files.mount --since "$since" --no-pager > $outfile

gjctl=$(grep "requires_propfind.*$basemissingfile" $outfile)
if [ $verbose -eq 1 ]; then
    echo "OUTPUT: $gjctl"
fi

# If we see "no propfind needed", we have failed;
grep -q "no propfind needed" $outfile

if [ $? -eq 0 ]; then
    fail=$((fail + 1))
    echo "FAIL: TEST 1"
else
    pass=$((pass + 1))
    echo "PASS: TEST 1"
fi

#### TEST 2
# Access the missing file. Some should trigger propfind, others not,
# depending on where the access is in the fibonacci backoff
# Start with the state of the previous test. We should be in an
# 8-second window where propfinds won't be triggered

# Create a gap for the new journalctl call
sleep 1

# For journalctl
since=$(date '+%Y-%m-%d %H:%M:%S')

attempt=0
attempts=3
sleeptime=2

while [ $attempt -lt $attempts ]
do
    if [ $verbose -eq 1 ]; then
        echo "$attempt: cat $missingfile"
        date '+%Y-%m-%d %H:%M:%S'
    fi

    cat $missingfile

    attempt=$(( attempt + 1 ))

    # Sleep 2 seconds. This should allow 3 attempts at the 
    # missing file while we are still in the fibonacci
    # backoff window
    if [ $verbose -eq 1 ]; then
        echo "Sleeping $sleeptime seconds"
    fi
    sleep $sleeptime

done

echo "journalctl -a -u srv-bindings-$bid-files.mount --since $since --no-pager > $outfile"
journalctl -a -u srv-bindings-$bid-files.mount --since "$since" --no-pager > $outfile

gjctl=$(grep "requires_propfind.*$basemissingfile" $outfile)
if [ $verbose -eq 1 ]; then
    echo "OUTPUT: $gjctl"
fi

# If we see "new propfind for path", we have failed;
grep -q "new propfind for path" $outfile

if [ $? -eq 0 ]; then
    fail=$((fail + 1))
    echo "FAIL: TEST 2"
else
    pass=$((pass + 1))
    echo "PASS: TEST 2"
fi

#### Clean Up
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
