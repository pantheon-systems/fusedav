Name: fusedav
Version: RPM_VERSION
Release: RPM_RELEASE%{?dist}
License: GPLv2
URL: https://github.com/pantheon-systems/fusedav
Vendor: Pantheon
Summary: Fusedav: Pantheon fuse-based DAV client
Source: fusedav-RPM_VERSION.tar.gz

BuildRequires: autoconf
BuildRequires: automake
BuildRequires: curl-devel
BuildRequires: expat-devel
BuildRequires: fuse-devel
BuildRequires: gcc
BuildRequires: glib2-devel
BuildRequires: jemalloc-devel
BuildRequires: leveldb-devel
BuildRequires: make
BuildRequires: systemd-devel
BuildRequires: uriparser-devel
BuildRequires: zlib-devel

Requires: fuse
Requires: fuse-libs
Requires: jemalloc
Requires: leveldb
Requires: uriparser

%description
fusedav is a fuse-based DAV client with extensions for performance.

%prep
%setup

%build
./autogen.sh
echo RPM_BUILD_ROOT = $RPM_BUILD_ROOT
CURL_LIBS="-lcurl" ./configure --prefix="${RPM_BUILD_ROOT}" \
  --bindir="/opt/pantheon/fusedav-release"
make

%install
%make_install

# HACK: rename binary
mv "${RPM_BUILD_ROOT}/opt/pantheon/fusedav-release/fusedav" \
  "${RPM_BUILD_ROOT}/opt/pantheon/fusedav-release/fusedav-release"

mkdir -p "${RPM_BUILD_ROOT}/usr/sbin"
install -m 0755 scripts/exec_wrapper/mount.fusedav_chan \
  "${RPM_BUILD_ROOT}/usr/sbin/mount.fusedav-release"

%check

# test that fusedav at least runs
echo "TEST OUTPUT: fusedav -V"
set +e
"${RPM_BUILD_ROOT}/opt/pantheon/fusedav-release/fusedav-release" -V
if [ "$?" != "0" ] ; then
  echo
  echo "fusedav binary seems broken, aborting"
  exit 1
fi
set -e

%files
%defattr(0644, root, root, 0755)
%attr(0755, root, root) /opt/pantheon/fusedav-release/fusedav-release
%attr(0755, root, root) /usr/sbin/mount.fusedav-release
