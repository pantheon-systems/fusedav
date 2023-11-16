#!/bin/sh
set -eou pipefail

# upload-gh-assets.sh is meant to be called automatically by Github Actions.
# Before calling this script, new-version.sh MUST already be loaded into our
# env.

T=$(mktemp -d)

# Upload artifacts with static/fixed names for ease of consumption.
for F in extract/RPMS/x86_64/*.rpm ; do
  n=$(echo $F | sed -e "s,.*/\([0-9A-Za-z-]*\)-${RPM_VERSION}-${RPM_RELEASE}\(.[0-9A-Za-z]*.x86_64.rpm\),\1\2,")
  echo "include ${F} as ${n}"
  cp $F "${T}/${n}"
done
for F in extract/SRPMS/*.rpm ; do
  n=$(echo $F | sed -e "s,.*/\([0-9A-Za-z-]*\)-${RPM_VERSION}-${RPM_RELEASE}\(.[0-9A-Za-z]*.src.rpm\),\1\2,")
  echo "include ${F} as ${n}"
  cp $F "${T}/${n}"
done

gh release upload $GITHUB_RELEASE_NAME ${T}/*.rpm
echo Done uploading release artifacts

rm -rf $T
