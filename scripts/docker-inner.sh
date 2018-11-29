#!/bin/sh
#
#
set -ex
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

# If the "/curl-7.4.6.0" directory exists in the build container it means we are using a
# custom build of curl linked with openssl. This is because libcurl on fedora < 27 used NSS instead of openssl
# https://fedoraproject.org/wiki/Changes/libcurlBackToOpenSSL
if [[ -d "/curl-7.46.0" ]]; then
  curl_libdir=$install_prefix/libs

  # copy pre-compiled vanilla libcurl into $install_prefix/$name/libs if the curl lib is part of the upstream container
  if [ ! -d "$curl_libdir"  ]; then
    mkdir -p $curl_libdir
  fi
  cp -R /curl-7.46.0/lib/.libs/* $curl_libdir

  # use our custom curl, and compile fusedav
  export CFLAGS="-Wl,-rpath,$curl_libdir,-rpath-link,$curl_libdir -L$curl_libdir -lcurl"
fi

./autogen.sh
CURL_LIBS="-lcurl" ./configure

make
make install

# this could be in the make-install, but for now lets keep the rpm sepparate from the build
if [ ! -d "$install_prefix" ] ; then
  mkdir -p $install_prefix
fi

# test that fusedav at least runs
set +e
/usr/local/bin/fusedav -V
/usr/local/bin/fusedav --help
if [ "1" != "$?" ] ; then
  echo "fusedav binary seems broken, failing to continue"
  exit 1
fi
set -e

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
  --depends  uriparser \
  --depends fuse-libs \
  --depends leveldb \
  --log=debug \
  $install_prefix \
  /usr/sbin/mount.$name

if [ ! -d "$rpm_dir/$fedora_release/fusedav" ]  ; then
  mkdir -p $rpm_dir/$fedora_release/fusedav
fi

mv *.rpm $rpm_dir/$fedora_release/fusedav/
