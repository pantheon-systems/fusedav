#! /bin/bash
set +e

usage()
{
cat << EOF
usage: $0 options

This script runs the command line tests

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -v      Verbose
EOF
}

verbose=0
while getopts "hi:v" OPTION
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

pass=0
fail=0

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# Do a du -sk on each file in the directory.
# If the size is non-zero, we consider this a pass, since this is
# a regression test against du returning zero when it shouldn't
# We know that some files actually correctly have size 0.
# Detect them by name. This is of course massively broken;
# if we run the test in a different order vis-a-vis other tests,
# we may get different results, or if we change the other tests.
# Ke garne? Maybe someone can harden this one.
for file in *
do 
    ret=$(du -sk $file); 
    size=$(echo $ret | awk '{print $1}'); 
    if [ $verbose -eq 1 ]; then
        echo "Size: $size"
    fi
    if [ $size -eq 0 ]
    then 
        # Sometimes files named zerolength are zerolength (sometimes not, but oh well)
        # So just pass them. Also the directory readwhatwas written is often empty,
        # so skip it too
        name=$(echo $ret | awk '{print $2}'); 
        if [ $verbose -eq 1 ]; then
            echo "Size was 0; name is $name"
        fi
        if [[ "$name" == zerolength* ]]
        then 
            pass=$(( pass + 1 ))
        elif [[ "$name" == readwhatwaswritten ]]
        then
            pass=$(( pass + 1 ))
        elif [[ "$name" == a ]]
        then
            pass=$(( pass + 1 ))
        else 
            fail=$(( fail + 1 ))
            echo "Size was 0; name is $name"
        fi
    else
        pass=$(( pass + 1 ))
    fi
done


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


