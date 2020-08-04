#!/bin/bash
#
#  wrapper for pushing rpm's up to both repos
#
bin="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
if [ -z "$(which package_cloud)" ]; then
  echo "Error no 'package_cloud' found in PATH"
  exit 1
fi

if [ -z "$1" ] ; then
  echo "Need to specify target repo: internal, internal-staging"
  exit 1
fi

BUILD_VERSIONS=${BUILD_VERSIONS:-22 28}
for i in $BUILD_VERSIONS ; do
  package_cloud push "pantheon/$1/fedora/$i" $bin/../pkg/$i/fusedav/*.rpm
done

# also push f28 build to centos8 for now
# TODO(jesse): build on centos 8
package_cloud push "pantheon/$1/el/8"  $bin/../pkg/28/fusedav/*.rpm
