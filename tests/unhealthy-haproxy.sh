#! /bin/bash

set +e

usage()
{
cat << EOF
usage: $0 options

This script tests saint mode by taking some haproxies up and down.

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
	iters=1
fi

pass=0
fail=0

if [ $verbose -eq 1 ]; then
    starttime=$(date +%s)
fi

# This test can only be run on a onebox.
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

# Needs to be in the files directory
if [ -f ./fusedav.conf ]; then
	cd files
fi

# If we have a fusedav.conf, that likely means we're in the right place
if [ ! -f ../fusedav.conf ]; then
	echo "ERROR: Need to cd to /srv/binding/<bid>/files directory"
	exit
fi

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

	if [ $onebox -eq 1 ]; then
		up=0

		t=$(date +%s); eo=$(($t % 16));
		# Always leave at least one haproxy running
		if [ $eo -eq 0 -o $eo -eq 1 -o $eo -eq 4 ]; then
			eo=5
		elif [ $eo -eq 2 ]; then
			eo=3
		elif [ $eo -eq 8 ]; then
			eo=9
		fi

		if [ $(($eo & $ha1m)) -ne 0 ]; then
			systemctl restart $ha1
			((up+=1))
		else
			systemctl stop $ha1
		fi

		if [ $(($eo & $ha2m)) -ne 0 ]; then
			systemctl restart $ha2
			((up+=2))
		else
			systemctl stop $ha2
		fi

		if [ $(($eo & $ha3m)) -ne 0 ]; then
			systemctl restart $ha3
			((up+=4))
		else
			systemctl stop $ha3
		fi

		if [ $(($eo & $ha4m)) -ne 0 ]; then
			systemctl restart $ha4
			((up+=8))
		else
			systemctl stop $ha4
		fi

		echo "ITER: $iter :: UP: $((10#${D2B[$up]})) :: EO: $eo"
	fi

	make -f /opt/fusedav/tests/Makefile run-unit-tests
done

if [ $onebox -eq 1 ]; then
	systemctl restart $ha1
	systemctl restart $ha2
	systemctl restart $ha3
	systemctl restart $ha4
fi

