#!/bin/sh
#
#
set -e
bin="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"

if [ "$#" -ne 4 ]; then
  echo "specify a channel, rpm dir, build num, and revision"
  exit 1
fi

fusedav_channel=$1
rpm_dir=$2
build=$3
epoch=$4

fedora_release=$(rpm -q --queryformat '%{VERSION}\n' fedora-release)
GITSHA=$(git log -1 --format="%h")
name="fusedav-$fusedav_channel"

version=$(cat $bin/../VERSION)
iteration=${epoch}.${GITSHA}
arch='x86_64'
url="https://github.com/pantheon-systems/${name}"
vendor='Pantheon'
description='Fusedav: Pantheon fuse-based DAV client'
fusedav_name="fusedav-$fusedav_channel"
install_prefix="/opt/pantheon/$name"

# copy pre-compiled vanilla libcurl into $install_prefix/$name/libs
# the curl lib is part of the upstream container
curl_libdir=$install_prefix/libs

if [ ! -d "$curl_libdir"  ]; then
  mkdir -p $curl_libdir
fi
cp -R /curl-7.46.0/lib/.libs/* $curl_libdir

export CFLAGS="-Wl,-rpath,$curl_libdir,-rpath-link,$curl_libdir -L$curl_libdir -lcurl"

# use our custom curl
CURL_LIBS="-lcurl" ./configure

# build fusedav
./autogen.sh
make
make install

# this could be in the make-install, but for now lets keep the rpm sepparate from the build
if [ ! -d "$install_prefix" ] ; then
  mkdir -p $install_prefix
fi

mv /usr/local/bin/fusedav $install_prefix/$name
cp $bin/exec_wrapper/mount.fusedav_chan /usr/sbin/mount.$name
chmod 755 /usr/sbin/mount.$name

fpm -s dir -t rpm \
  --name "${name}" \
  --version "${version}" \
  --iteration "${iteration}" \
  --architecture "${arch}" \
  --url "${url}" \
  --vendor "${vendor}" \
  --description "${description}" \
  --log=debug \
  $install_prefix/$name \
  /usr/sbin/mount.$name

if [ ! -d "$rpm_dir/$fedora_release/fusedav" ]  ; then
  mkdir -p $rpm_dir/$fedora_release/fusedav
fi
mv *.rpm $rpm_dir/$fedora_release/fusedav/
