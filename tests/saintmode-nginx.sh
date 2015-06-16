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

# If we have a fusedav.conf, that likely means we're in the right place
if [ -f ../fusedav.conf ]; then
	cd ..
fi

if [ ! -f ./fusedav.conf ]; then
	echo "ERROR: Need to cd to /srv/binding/<bid> directory"
	exit
fi

iter=1
while [ $iter -le $iters ]
do
	iter=$((iter + 1))

	t=$(date +%s); eo=$(($t % 2));
	if [ $eo -eq 0 ]; then
		systemctl restart nginx_valhalla.service
		echo "UP"
	else
		systemctl stop nginx_valhalla.service
		echo "DOWN"
	fi
	for file in $(find files)
	do 
		# echo $file
		res=$(curl -s -I http://dev-panopoly-two.onebox.pantheon.io/sites/default/$file | grep HTTP)
		if [[ ! $res =~ '200' && ! $res =~ '301' && ! $res =~ '403' ]]; then
			echo "ERROR: $res :: $file"
		fi
	done
done
systemctl restart nginx_valhalla.service

cd files
