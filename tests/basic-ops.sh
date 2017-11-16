#! /bin/bash
set +e

echo "ENTER: basic-ops.sh $@"
usage()
{
cat << EOF
usage: $0 options

This script runs the basic ls test (for the dual-bindings.sh test)

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -b      Binding dir and id
   -c      Command line args
   -r      Add -R to ls
   -v      Verbose
EOF
}

iters=0
verbose=0
binding="none"
basedir="basic-ops"
testdir="basic-ops-dir"
dir=$basedir/$testdir
file="basic-ops-file"
cmd="none"
declare -i ret

while getopts "hri:b:c:d:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
             ;;
         b)
             binding=$OPTARG
             ;;
         c)
             cmd=$OPTARG
             ;;
         d)
             dir=$OPTARG
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

if [ $binding == "none" ]; then
    echo "Binding (with dir and id) is required. Exiting ..."
    exit
fi

if [ $iters -eq 0 ]; then
    iters=1
fi

list() {
    echo "list: ls -al $1/$2"
    ls -al $1/$2
    ret=$?
    return $ret 
}

listR() {
    echo "listR: ls -alR $1/$2"
    ls -alR $1/$2
    ret=$?
    return $ret 
}

makedir() {
    echo "makedir: mkdir -p $1/$2"
    mkdir -p $1/$2
    ret=$?
    return $ret 
}

readfile() {
    echo "read: cat $$file > /dev/null"
    cat $file > /dev/null
    ret=$?
    return $ret 
}

writefile() {
    echo "writefile: head -c 67 /dev/urandom > $1/$2/$3-$4"
    head -c 67 /dev/urandom > $1/$2/$3-$4
    ret=$?
    return $ret
}

removedir() {
    echo "removedir: rmdir $1/$2"
    rmdir $1/$2
    ret=$?
    return $ret 
}

removefiles() {
    echo "removefiles: rm -f $1/$2/*"
    rm -f $1/$2/*
    ret=$?
    return $ret 
}

# get commands from string and put in array
commands=(${cmd//;/ })
if [ $verbose -eq 1 ]; then
    echo "COMMANDS: $cmd :: ${commands[*]}"
fi

pass=0
fail=0

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

for cmd in "${commands[@]}"; do
    result=0
    expect_failure=0
    if [ $cmd == "list" ]; then
        list $binding $dir
        ret=$?
    elif [ $cmd == "listbase" ]; then
        list $binding $basedir
        ret=$?
    elif [ $cmd == "flist" ]; then
        expect_failure=1
	echo "--Expect Failure"
        list $binding $dir
        ret=$?
    elif [ $cmd == "listR" ]; then
        listR $binding $dir
        ret=$?
    elif [ $cmd == "listRbase" ]; then
        listR $binding $basedir
        ret=$?
    elif [ $cmd == "flistR" ]; then
        expect_failure=1
	echo "--Expect Failure"
        listR $binding $dir
        ret=$?
    elif [ $cmd == "makedir" ]; then
        makedir $binding $dir
        ret=$?
    elif [ $cmd == "fmakedir" ]; then
        expect_failure=1
	echo "--Expect Failure"
        makedir $binding $dir
        ret=$?
    elif [ $cmd == "writefile" ]; then
        fail=0
        pass=0
	iter=1
        while [ $iter -le $iters ]
        do
            echo "iter: $iter"
	    writefile $binding $dir $file $iter
            ret=$?
	    # We will also increment once more below, so one of the values will be off by one.
	    # Am I worried?
            if [ "$ret" -ne 0 ]; then
                fail=$((fail + 1))
            else
                pass=$((pass + 1))
            fi
            iter=$((iter + 1))
        done
    elif [ $cmd == "fwritefile" ]; then
        expect_failure=1
	echo "--Expect Failure"
        fail=0
        pass=0
        while [ $iter -le $iters ]
        do
            echo "iter: $iter"
	    writefile $binding $dir $file $iter
            ret=$?
	    # We will also increment once more below, so one of the values will be off by one.
	    # Am I worried?
	    # Reverse meaning of ret
            if [ "$ret" -eq 0 ]; then
                fail=$((fail + 1))
            else
                pass=$((pass + 1))
            fi
            iter=$((iter + 1))
        done
    elif [ $cmd == "readfile" ]; then
        for file in $binding/$dir; do
            readfile $file
            ret=$?
	    # We will also increment once more below, so one of the values will be off by one.
	    # Am I worried?
            if [ "$ret" -ne 0 ]; then
                fail=$((fail + 1))
            else
                pass=$((pass + 1))
            fi
        done
    elif [ $cmd == "freadfile" ]; then
        expect_failure=1
	echo "--Expect Failure"
        for file in $binding/$dir; do
            readfile $file
            ret=$?
	    # We will also increment once more below, so one of the values will be off by one.
	    # Am I worried?
	    # Reverse meaning of ret
            if [ "$ret" -eq 0 ]; then
                fail=$((fail + 1))
            else
                pass=$((pass + 1))
            fi
        done
    elif [ $cmd == "removefiles" ]; then
        removefiles $binding $dir
        ret=$?
    elif [ $cmd == "fremovefiles" ]; then
        expect_failure=1
	echo "--Expect Failure"
        removefiles $binding $dir
        ret=$?
    elif [ $cmd == "removedir" ]; then
        removedir $binding $dir
        ret=$?
    elif [ $cmd == "fremovedir" ]; then
        expect_failure=1
	echo "--Expect Failure"
        removedir $binding $dir
        ret=$?
    else
        echo "Unknowned command: $cmd"
        ret=0
    fi

    # If this is an expect failure call, reverse meaning of ret
    if [ $expect_failure -ne 0 ]; then
	if [ $ret -eq 0 ]; then
	    ret=1
	else
	    ret=0
	fi
	echo "EXPECTED FAILURE: $ret"
    fi

    if [ "$ret" -ne 0 ]; then
        fail=$((fail + 1))
        echo "FAIL"
    else
        pass=$((pass + 1))
        echo "PASS"
    fi
done


if [ $verbose -eq 1 ]; then
    endtime=$(date +%s)
    elapsedtime=$(( $endtime - $starttime ))
    echo "Elapsed time: $elapsedtime"
fi

if [ $fail -ne 0 ]; then
    echo "FAIL: times failed $fail; files passed $pass"
else
    echo "PASS: times passed $pass"
fi

echo "EXIT: basic-ops.sh"
exit $fail
