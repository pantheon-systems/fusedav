#!/bin/sh
#
# build-rpm.sh is meant to be run inside a `dev` or `compile` container
# (as defined in Dockerfile in the root of this repo).
#
# It should be started from the root of the repo.
#
# Upon success, the fusedav RPM will be written to the pkg/28/fusedav
# directory.
# 
# RPM version string creation is a bit weird.  The VERSION file is expected to
# contain something like `0.0.1+3`, where 0.0.1 is the proper version and 3
# is the build number (which should be populated from CIRCLE_BUILD_NUM
# upstream).
# 
# `iteration` is the timestamp (in seconds since the epoch) followed by a
# period and the 7-character git commit hash.
#
# All together, the RPM version/iteration string ends up looking like
# `0.0.1+3-1698000000.abc1234`.
#
# Note that the RPM version and iteration strings are SEPARATE from the
# SemVer string embedded within the fusedav binary.
#
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "specify a channel"
  exit 1
fi

if [ ! -r VERSION ] ; then
  echo "VERSION file is missing; cannot continue"
fi

# fusedav_channel may be: dev, stage, yolo, release
fusedav_channel=$1

# build vars from environment
fedora_release=$(rpm -q --queryformat '%{VERSION}\n' fedora-release)
name="fusedav-${fusedav_channel}"
version=$(cat VERSION)

arch=$(uname -m) # typically x86_64
url="https://github.com/pantheon-systems/${name}"
vendor='Pantheon'
description='Fusedav: Pantheon fuse-based DAV client'

# Note that the ".fc28" RPM release/iteration suffix is arbitrarily
# added here.  Provision should be made for using a different string
# if/when building on other distributions/versions.
if [ -n "${CIRCLE_SHA1:-}" ]; then
  iteration="$(date +%s).$(echo $CIRCLE_SHA1 | cut -c -7).fc28"
else
  iteration="$(date +%s).$(git rev-parse --short HEAD).fc28"
#  if [ -n "$(git status --porcelain)" ] ; then
#    iteration="${iteration}-dirty"
#  fi
fi

# rpm_build_root is used by `make install` to write fusedav.
rpm_build_root="${HOME}/fusedav_build_root"

# install_prefix is the final home of the fusedav binary, relative to rpm_build_root.
install_prefix="opt/pantheon/${name}"

# start the build
./autogen.sh
mkdir -p $rpm_build_root
CURL_LIBS="-lcurl" ./configure --prefix="${rpm_build_root}"
make
make install

# test that fusedav at least runs
set +e
fusedav_bin="${rpm_build_root}/bin/fusedav"
echo
echo "TEST OUTPUT: fusedav -V"
"${fusedav_bin}" -V
echo
echo "TEST OUTPUT: fusedav --help"
"${fusedav_bin}" --help
if [ "$?" != "1" ] ; then
  echo
  echo "fusedav binary at ${fusedav_bin} seems broken, aborting"
  exit 1
fi
echo
set -e

mkdir -p "${rpm_build_root}/${install_prefix}"
mv $fusedav_bin "${rpm_build_root}/${install_prefix}"

mkdir -p "${rpm_build_root}/usr/sbin"
install -m 0755 scripts/exec_wrapper/mount.fusedav_chan "${rpm_build_root}/usr/sbin/mount.${name}"

# fpm will not clobber, so ensure file is not present
#rpm_version=$(echo $version | sed -e 's/-/_/g')
#rpm_iteration=$(echo $iteration | sed -e 's/-/_/g')
rpm_target="${name}-${version}-${iteration}.${arch}.rpm"
rm -f $rpm_target

echo "BUILD RPM"
fpm -s dir -t rpm \
  --name "${name}" \
  --version "${version}" \
  --iteration "${iteration}" \
  --architecture "${arch}" \
  --url "${url}" \
  --vendor "${vendor}" \
  --description "${description}" \
  --depends uriparser \
  --depends fuse-libs \
  --depends leveldb \
  --log=info \
  --chdir=$rpm_build_root \
  $install_prefix \
  "usr/sbin/mount.${name}"

mkdir -p "pkg/${fedora_release}/fusedav"
mv $rpm_target "pkg/${fedora_release}/fusedav/"
echo "${rpm_target}" > LATEST_RPM
echo "fusedav RPM written to pkg/${fedora_release}/fusedav/${rpm_target}"
