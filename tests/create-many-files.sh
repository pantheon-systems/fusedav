#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

OPTIONS:
   -h      Show this message
   -n      Number of files
   -v      Verbose
EOF
}

numfiles=0
verbose=0
startnum=0

while getopts "hn:s:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         n)
	     numfiles=$OPTARG
             ;;
         s)
	     startnum=$OPTARG
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

if [ $numfiles -eq 0 ]; then
    numfiles=1000
fi

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# append; this also creates a file for later tests
head -c 64 /dev/urandom > urlencode.file

numfile=1
while [ $numfile -le $numfiles ]
do
    filenum=$(( $numfile + $startnum ))
    if [ $verbose -eq 1 ]; then
        echo "$numfile: head -c 64 /dev/urandom > create-many-files-$filenum"
    fi
    head -c 64 /dev/urandom > create-many-files-$filenum
    numfile=$(( numfile + 1 ))
done

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi
