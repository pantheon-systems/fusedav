#! /bin/bash

set +e

usage()
{
cat << EOF
usage: $0 options

This script tests saint mode by taking haproxies up and down.

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

# This test can only be run on a onebox.
# It needs to take the haproxies up and down.
# If run outside of a onebox, it would be run on an endpoint,
# and there is no facility there to take valhalla(yolo)
# haproxies up and down
if [ ! -f /etc/systemd/system/haproxy_valhalla21_onebox.service ]; then
	echo "ERROR: This test needs to be run on a onebox."
	exit
fi

# Most tests need to be in the files directory, but this one needs to be
# one up.
if [ -f ../fusedav.conf ]; then
	cd ..
fi

# If we have a fusedav.conf, that likely means we're in the right place
if [ ! -f ./fusedav.conf ]; then
	echo "ERROR: Need to cd to /srv/binding/<bid> directory"
	exit
fi

# These are onebox haproxies
ha1=haproxy_valhalla21_onebox.service
ha1m=1
ha2=haproxy_valhalla22_onebox.service
ha2m=2
ha3=haproxy_valhalla23_onebox.service
ha3m=4
ha4=haproxy_valhalla.service
ha4m=8
D2B=({0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1}{0..1})

iter=1
while [ $iter -le $iters ]
do
	iter=$((iter + 1))

	up=0

	t=$(date +%s); eo=$(($t % 16));

	if [ $(($eo & $ha1m)) -eq 0 ]; then
		systemctl restart $ha1
		((up+=1))
	else
		systemctl stop $ha1
	fi

	if [ $(($eo & $ha2m)) -eq 0 ]; then
		systemctl restart $ha2
		((up+=2))
	else
		systemctl stop $ha2
	fi

	if [ $(($eo & $ha3m)) -eq 0 ]; then
		systemctl restart $ha3
		((up+=4))
	else
		systemctl stop $ha3
	fi

	if [ $(($eo & $ha4m)) -eq 0 ]; then
		systemctl restart $ha4
		((up+=8))
	else
		systemctl stop $ha4
	fi

	if [ $verbose -gt 0 ]; then
		echo "UP: $((10#${D2B[$up]}))"
	fi

	for file in $(find files)
	do 
		# echo $file
		res=$(curl -s -I http://dev-panopoly-two.onebox.pantheon.io/sites/default/$file | grep HTTP)
		if [ $verbose -gt 0 ]; then
			#printf "SUCCEED: %s: curl: %s :: %s\n" "$0" "$res" "$file"
			printf "SUCCEED: %s: %s :: %s\n" "$0" "$file" "$res"
		fi

		if [[ ! $res =~ '200' && ! $res =~ '301' && ! $res =~ '403' ]]; then
			printf "ERROR: %s: %s :: %s\n" "$0" "$file" "$res"
			fail=$((fail + 1))
		else
			pass=$((pass + 1))
		fi
	done
done
systemctl restart $ha1
systemctl restart $ha2
systemctl restart $ha3
systemctl restart $ha4

cd files

if [ $fail -ne 0 ]; then
	echo "FAIL: curl calls failed: $fail; curl calls passed $pass"
else
	echo "PASS: curl calls passed $pass"
fi

