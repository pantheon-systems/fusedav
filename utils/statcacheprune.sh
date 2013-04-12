#! /bin/bash

set -e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

OPTIONS:
   -h      Show this message
   -f      Number of files per directory
   -d      Number of directories per level (up to 4)
   -v      Verbose
EOF
}

numfiles=0
numdirs=0
verbose=0
while getopts “hf:d:v” OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         f)
             numfiles=$OPTARG
             ;;
         d)
             numdirs=$OPTARG
             if [ $numdirs -gt 4 ]; then
                numdirs=4
            fi
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
    numfiles=64
fi

if [ $numdirs -eq 0 ]; then
    numdirs=2
fi

filescreated=0
fail=0
dirscreated=0

pecho() {
    if [ $verbose -eq 1 ]; then
        echo $1
    fi
}

compare() {
    # If the first file is zero-size, we fail
    # else use cmp to see if files are identical
    if [ ! -s $1 ]; then
        fail=$((fail + 1))
        pecho "Failed on $1: zero-size"
    else
        cmp -s $1 $2
        if [ $? -eq 0 ]; then
            filescreated=$((filescreated + 1))
        else
            fail=$((fail + 1))
            pecho "Failed on $1 $2"
        fi
    fi
}

check_dir() {
    if [ -d $1 ]; then
        dirscreated=$((dirscreated + 1))
    else
        fail=$((fail + 1))
        pecho "Failed on $1"
    fi
}

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi


function add_files() {
    dir=$1
    name=file$2
    pecho "Adding files for $dir/$name"
    fiter=1
    while [ $fiter -le $numfiles ]
    do
        file=file$name-$fiter.txt
        cp $basefile $dir/$file
        compare $basefile $dir/$file
        fiter=$((fiter + 1))
    done
}

function pick_dir() {
    if [ $1 == "numbers" ]; then
        case $2 in
            1 )
                dir=one ;;
            2 )
                dir=two ;;
            3 )
                dir=three ;;
            4 )
                dir=four ;;
        esac
    else
        case $2 in
            1 )
                dir=abc ;;
            2 )
                dir=def ;;
            3 )
                dir=ghi ;;
            4 )
                dir=jkl ;;
        esac
    fi
    echo $dir
}

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

basefile=basefile
rm -f $basefile > /dev/null 2>&1
head -c 64 /dev/urandom > $basefile 2>&1

# at each level, create 4 directories
diriter=1
while [ $diriter -le $numdirs ]
do
    dir="statcacheprune-"$(pick_dir "numbers" $diriter)
    pecho "Removing $dir"
    rm -rf $dir
    pecho "Making $dir"
    mkdir -p $dir
    check_dir $dir
    add_files $dir $dir
    diriter=$((diriter + 1))

    sdiriter=1
    while [ $sdiriter -le $numdirs ]
    do
        sdir=$(pick_dir "alpha" $sdiriter)
        dir=$dir/$sdir
        pecho "Making $dir"
        mkdir -p $dir
        check_dir $dir
        add_files $dir $sdir
        sdiriter=$((sdiriter + 1))

        ssdiriter=1
        while [ $ssdiriter -le $numdirs ]
        do
            ssdir=$(pick_dir "numbers" $ssdiriter)
            dir=$dir/$ssdir
            pecho "Making $dir"
            mkdir -p $dir
            check_dir $dir
            add_files $dir $ssdir
            ssdiriter=$((ssdiriter + 1))

            sssdiriter=1
            while [ $sssdiriter -le $numdirs ]
            do
                sssdir=$(pick_dir "alpha" $sssdiriter)
                dir=$dir/$sssdir
                pecho "Making $dir"
                mkdir -p $dir
                check_dir $dir
                add_files $dir $sssdir
                sssdiriter=$((sssdiriter + 1))
            done
        done
    done
done

if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    pecho "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: fail $fail; files created $filescreated; dirs created $dirscreated"
else
    echo "PASS: files created $filescreated; dirs created $dirscreated"
fi

