#!/bin/bash
#
# push_packagecloud.sh pushes all RPMs for a given Fedora version to the
# specified Packagecloud repository.
#
# Packagecloud authn must be handled elsewhere, either via setting
# PACKAGECLOUD_TOKEN or in ${HOME}/.packagecloud.

if ! command -v package_cloud > /dev/null; then
  echo "package_cloud not in PATH, aborting"
  exit 1
fi

if [ -z "$1" ] ; then
  echo "Need to specify target repo: internal, internal-staging"
  exit 1
fi

BUILD_VERSIONS=${BUILD_VERSIONS:-28}
for i in $BUILD_VERSIONS ; do
  package_cloud push "pantheon/$1/fedora/$i" pkg/$i/fusedav/*.rpm
done
