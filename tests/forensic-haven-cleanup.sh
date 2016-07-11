#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

OPTIONS:
   -h      Show this message
   -v      Verbose
EOF
}

verbose=0
while getopts "hv" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
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

# Most tests need to be in the files directory, but this one needs to be
# one up.
if [ -f ../fusedav.conf ]; then
	cd ..
fi

if [ ! -f fusedav.conf ]; then
    echo "ERROR: Need to be in /srv/bindings/<bid> directory"
    exit
fi

fail=0

create_files() {
    number=$1
    age=$2
    counter=0
    while [ $counter -lt $number ]; do
        # create files with some content
        head -256 /dev/urandom > cache/forensic-haven/fhfilename-$age
        # touch to make it the proper age
        touch -d "$age hours ago" cache/forensic-haven/fhfilename-$age
        # make next file one hour older than this one
        let age=age+1
        # increment counter
        let counter=counter+1
    done
}

expect_files() {
    expected=$1
    sleep 3
    fl=$(ls cache/forensic-haven)
    nf=$(ls cache/forensic-haven | wc -l)
    if [ $nf -ne $expected ]; then
        # Error
        echo "Expected $expected files in forensic-haven; got $nf"
	echo "Files left: $fl"
        let fail=fail+1
    elif [ $verbose -gt 0 ]; then
	echo "Pass: $nf files"
    fi
}

# Are there different scenarios we want to run, in a loop?
# 1. 7 files
# 2. All files older than 64 hours except one which triggered forensic-haven
# 3. Many files in each of the buckets
# 4. Fewer than 7 files

# Write x number of files to forensic haven with each of several timestamps.
# More than 64 hours old; 16-64, 4-16, 1-4
# Trigger an error file (too large is easiest)
# Decide what is expected
# Log the activity and see if it's as expected
# Check the final result

# Create the big file, larger than 256M, to trigger forensic-haven
if [ $verbose -gt 0 ]; then
    echo "Creating big file; be patient"
fi
head -c258m /dev/urandom > big-file

# Scenario 1
echo "Scenario 1"
create_files 2 1
create_files 2 4
create_files 2 16
create_files 1 64
# Trigger forensic-haven
cp big-file files > /dev/null 2>&1
# Expect
# Started with 7 files, added 2 for big-files and big-files.txt.
# Removed the file older than 64 hours, left 8
# Removed 2 files older than 16 hours, left 6
expect_files 6
# Cleanup
rm -f cache/forensic-haven/*

# Scenario 2
echo "Scenario 2"
create_files 7 64
# Trigger forensic-haven
cp big-file files > /dev/null 2>&1
# Expect
# Added big-files and big-files.txt
# Deleted all 7 previous files older than 64
expect_files 2
# Cleanup
rm -f cache/forensic-haven/*

# Scenario 3
echo "Scenario 3"
create_files 3 1
create_files 10 4
create_files 8 16
create_files 4 64
# Trigger forensic-haven
cp big-file files > /dev/null 2>&1
# Expect
# Added big-files and big-files.txt, for 27 files
# Deleted 4 older than 64 hours, for 23.
# Deleted 8 older than 16 hours, for 15.
# Deleted 10 older than 4 hours, for 5
expect_files 5
# Cleanup
rm -f cache/forensic-haven/*

# Scenario 4
echo "Scenario 4"
create_files 1 1
create_files 1 4
create_files 1 16
create_files 1 64
# Trigger forensic-haven
cp big-file files > /dev/null 2>&1
# Expect
# We should get rid of the file older than 64 hours but keep the rest
# Added big-files and big-files.txt for 6 files
# Removed 1 file older than 64 hours, for 5
expect_files 5
# Cleanup
rm -f cache/forensic-haven/*

# Put us back in the files directory since most tests need to be there
cd files

if [ $fail -gt 0 ]; then
    echo "FAIL: $fail failures"
else
    echo "PASS"
fi

