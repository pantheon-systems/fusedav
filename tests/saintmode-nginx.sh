#! /bin/bash

set +e

usage()
{
cat << EOF
usage: $0 options

This script tests saint mode by taking valhalla nginx up and down.

OPTIONS:
   -h      Show this message
   -i      Number of iterations
   -v      Verbose
EOF
}

verbose=0
iters=0

while getopts "hi:v" OPTION
do
     case $OPTION in
         h)
             usage
             exit 1
             ;;
         i)
             iters=$OPTARG
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
	iters=4
fi

pass=0
fail=0

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# If run on a onebox, it will take nginx_valhalla up and down.
# If run outside of a onebox, it would be run on an endpoint,
# and there is no facility there to take valhalla(yolo)
# services up and down, so for those tests, other measures
# need to be taken (e.g. script on each valhallayolo node
# to stop/restart the nginx service)
if [ -f /etc/systemd/system/haproxy_valhalla21_onebox.service ]; then
	echo "Running on a onebox."
	onebox=1
else
	onebox=0
fi


# Most tests need to be in the files directory, but this one needs to be
# one up.

# If we have a fusedav.conf, that likely means we're in the right place
if [ -f ../fusedav.conf ]; then
	cd ..
fi

if [ ! -f ./fusedav.conf ]; then
	echo "ERROR: Need to cd to /srv/binding/<bid> directory"
	exit
fi

uri=$(grep Description /etc/systemd/system/php_fpm_$(pwd | sed s#/srv/bindings/## | sed s#/files##).service | sed s#.*uri=##)
iter=1

# Set up some files and directories for the test
if [ $onebox -eq 1 ]; then
	systemctl restart nginx_valhalla.service
fi
tmpdir1="files/mydir.${0##*/}-$$"
#echo "MKDIR: $tmpdir1"
mkdir $tmpdir1
for idx in {1..12}; do
	# create a random file
	filelist[$idx]=`mktemp files/myfile.XXX`
	# make it not empty
	echo "abc" > ${filelist[$idx]}
	#echo "FILE: ${filelist[$idx]}"
	#cat ${filelist[$idx]}
done

while [ $iter -le $iters ]
do
	iter=$((iter + 1))

	if [ $onebox -eq 1 ]; then
		t=$(date +%s); eo=$(($t % 2));
		if [ $eo -eq 0 ]; then
			systemctl restart nginx_valhalla.service
			echo "UP"
		else
			systemctl stop nginx_valhalla.service
			echo "DOWN"
		fi
	fi
	for file in $(find files)
	do 
		# echo $file
		res=$(curl -s -H "Cache-Control: no-cache" -H "X-Bypass-Cache: 1" -I http://$uri/sites/default/$file | grep HTTP)
		if [ $verbose -gt 0 ]; then
			printf "SUCCEED: %s: %s : %s :: %s\n" "$0" "$uri" "$file" "$res"
		fi

		if [[ ! $res =~ '200' && ! $res =~ '301' && ! $res =~ '403' ]]; then
			printf "ERROR: %s: %s : %s :: %s\n" "$0" "$uri" "$file" "$res"
			fail=$((fail + 1))
		else
			pass=$((pass + 1))
		fi
		if [ $verbose -gt 0 ]; then
			sleep 1
		fi
	done

done

# Need to stop the service for the following
if [ $onebox -eq 1 ]; then
	systemctl stop nginx_valhalla.service
	sleep 2
fi

# remove the directory created above; should get network failure
res=$(rmdir $tmpdir1 2>&1)
if [[ ! $res =~ "Network is down" ]]; then
	printf "ERROR: rmdir: %s: %s: %s\n" "$0", "$tmpdir1", "$res"
	fail=$((fail + 1))
else
	pass=$((pass + 1))
	#printf "SUCCESS: rmdir: %s: %s: %s\n" "$0", "$tmpdir1", "$res"
fi

# create a new directory; should get network failure
tmpdir2="files/mydir2.${0##*/}-$$"
res=$(mkdir $tmpdir2 2>&1)
if [[ ! $res =~ "Network is down" ]]; then
	printf "ERROR: mkdir: %s: %s: %s\n" "$0", "$tmpdir2", "$res"
	fail=$((fail + 1))
else
	pass=$((pass + 1))
	#printf "SUCCESS: mkdir: %s: %s: %s\n" "$0", "$tmpdir2", "$res"
fi

# cat each of the files created above; should get "abc"
for file in ${filelist[@]}; do
	res=$(cat $file)
	if [[ ! "$res" =~ "abc" ]]; then
		printf "ERROR: cat file: %s: %s: %s\n" "$0", "$file", "$res"
		fail=$((fail + 1))
	else
		pass=$((pass + 1))
		#printf "SUCCESS: cat file: %s: %s: %s\n" "$0", "$file", "$res"
	fi
done

# remove each of the files created above; should get network failure
for file in ${filelist[@]}; do
	res=$(rm -f $file 2>&1)
	if [[ ! $res =~ "Network is down" ]]; then
		printf "ERROR: rm file: %s: %s: %s\n" "$0", "$file", "$res"
		fail=$((fail + 1))
	else
		pass=$((pass + 1))
		#printf "SUCCESS: rm file: %s: %s: %s\n" "$0", "$file", "$res"
	fi
done

if [ $onebox -eq 1 ]; then
	systemctl restart nginx_valhalla.service
	sleep 2
fi

for file in ${filelist[@]}; do
	rm -f $file
done
rmdir $tmpdir1
rmdir $tmpdir2

cd files

if [ $fail -ne 0 ]; then
	echo "FAIL: curl calls failed: $fail; curl calls passed $pass"
else
	echo "PASS: curl calls passed $pass"
fi

