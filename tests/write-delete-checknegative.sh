#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script tests that files written and deleted create a negative entry in
the stat cache and those written and not deleted don't.

This script gets the pid of the binding, sends a SIGUSR2 signal which dumps
the stat cache, then calls journalctl to get log messages, and uses their content
to ascertain success or failure.

OPTIONS:
   -h      Show this message
   -v      Verbose
   -n      Number of iterations.
EOF
}

iters=16
verbose=0

while getopts "hvn:" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
	 n)
             iters=$OPTARG
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

if [ -f ../fusedav.conf ]; then
	cd ..
fi

if [ ! -f fusedav.conf ]; then
    echo "ERROR: Need to be in /srv/bindings/<bid> directory: $(pwd)"
    exit
fi

# e.g. /srv/bindings/<bid>
path=$(pwd)
# binding id
bid=${path##*/}
# base name
bn=write-delete-checknegative
# base dir
bd=files/$bn-dir
# base file
bf=$bd/$bn
# output file for journalctl, from which are read results
outfile=/tmp/$bn.out

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

iter=0

pass=0
fail=0

##### TEST 1
# Create a number of iles

if [ $verbose -eq 1 ]; then
    echo "mkdir $bd"
fi

rm -f $bd/*
rmdir $bd

mkdir $bd > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Failed to make directory $bd. Exiting..."
    exit
fi

# For journalctl
since=$(date '+%Y-%m-%d %H:%M:%S')

# Reset the state of the files for the first attempts.
# If this test has already been run and the files still
# exist in the stat cache, the results are invalid
if [ $verbose -eq 1 ]; then
    btool invalidate srv-bindings-$bid-files.mount
else
    btool invalidate srv-bindings-$bid-files.mount > /dev/null 2>&1
fi

# PID of fusedav mount; needed later to send it a signal to dump stat cache
fdpid=$(ps -A -o pid,cmd | grep fusedav | grep $bid | grep fusedav.conf | awk '{print $1}')
if [ $verbose -eq 1 ]; then
    echo "PID: $fdpid"
fi

# Create the files ...
while [ $iter -lt $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: echo $bf-$iter.file > $bf-$iter.file"
    fi

    echo "$bf-$iter.file" > $bf-$iter.file

    iter=$(( iter + 1 ))
done

# Delete some files
iter=0
while [ $iter -lt $iters ]
do
    # Delete all files on iter % 3; do not delete the others
    df=$(( iter % 3 ))
    if [ $df -eq 0 ]; then
        if [ $verbose -eq 1 ]; then
            echo "$iter: rm -f $bf-$iter.file"
        fi
        rm -f $bf-$iter.file
    fi

    iter=$(( iter + 1 ))
done

# Send signal to dump stat cache to journalctl
kill -SIGUSR2 $fdpid

# Sleep some time to make sure the dump completes
sleep 8

if [ $verbose -eq 1 ]; then
    echo "journalctl -a -u srv-bindings-$bid-files.mount --since $since --no-pager > $outfile"
fi
journalctl -a -u srv-bindings-$bid-files.mount --since "$since" --no-pager > $outfile

# Check for positive or negative for files
iter=0
while [ $iter -lt $iters ]
do
    if [ $verbose -eq 1 ]; then
        echo "$iter: grep *stat_cache_walk:.*$bn-$iter.file.*positive" $outfile
    fi
    pn=$(grep "stat_cache_walk:.*$bn-$iter.file.*positive" $outfile)
    if [ $? -eq 0 ]; then
        pos=1
    else
        if [ $verbose -eq 1 ]; then
            echo "$iter: grep *stat_cache_walk:.*$bn-$iter.file.*negative" $outfile
        fi
        pn=$(grep "stat_cache_walk:.*$bn-$iter.file.*negative" $outfile)
        if [ $? -eq 0 ]; then
            neg=1
        fi
    fi
    if [ $verbose -eq 1 ]; then
        echo "$iter: grep on $bn-$iter.file: $pn"
    fi
    df=$(( iter % 3 ))
    if [ $df -eq 0 ]; then
	# Should have been deleted, so we should not expect 'positive' in the grep
	if [ $neg ]; then
	    pass=$((pass + 1))
            if [ $verbose -eq 1 ]; then
		echo "Passed on $bn-$iter.file: did not get positive"
	    fi
	else
            fail=$((fail + 1))
            if [ $verbose -eq 1 ]; then
		echo "Failed on $bn-$iter.file: expected negative, got positive"
	    fi
	fi
    else
	# Should not have been deleted, so we should expect 'positive' in the grep
	if [ $pos ]; then
	    pass=$((pass + 1))
            if [ $verbose -eq 1 ]; then
		echo "Passed on $bn-$iter.file: got positive"
	    fi
	else
            fail=$((fail + 1))
            if [ $verbose -eq 1 ]; then
		echo "Failed on $bn-$iter.file: expected positive but did not get it"
	    fi
	fi
    fi

    iter=$(( iter + 1 ))
done

#### Clean Up
if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: files failed $fail; files passed $pass"
else
    echo "PASS: files passed $pass"
fi
