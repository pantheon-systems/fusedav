Fusedav
=======

[![Unsupported](https://img.shields.io/badge/Pantheon-Unsupported-yellow?logo=pantheon&color=FFDC28)](https://pantheon.io/docs/oss-support-levels#unsupported)

Fusedav Client
--------------

This is a fuse-based DAV client with extensions for performance.
This will run against any standard DAV implementation, i.e.
`pywebdav` (see tests).

Installation
------------

1. ```git clone git://github.com/pantheon-systems/fusedav.git```
2. ```git clean -f -x -d && ./autogen.sh && ./configure && make```

Usage
-----

Use the ```-V``` flag to see libraries.
```
$ src/fusedav -V
fusedav version 2.0.42-bccf93b
LevelDB version 1.20
libcurl/7.59.0 OpenSSL/1.1.0i zlib/1.2.11 libidn2/2.0.5 libpsl/0.20.2 (+libidn2/2.0.4) libssh/0.8.5/openssl/zlib nghttp2/1.32.1
FUSE library version: 2.9.7
```

Debug/Develop
-----
Running this docker script in debug mode will build a fedora-22 container with the local source mounted inside it suitable to build fusedav.
```
BUILD_VERSIONS=22 BUILD_DEBUG=1  ./scripts/docker-outer.sh
```

libcurl and OpenSSL
-------------------

FuseDAV requires libcurl linked with OpenSSL. On Fedora versions before 27 the
provided libcurl is linked against NSS and you need to provide your own libcurl
linked against OpenSSL.

Contributing
------------

1. Fork it.
2. Create a branch (`git checkout -b my_new_features`)
3. Commit your changes (`git commit -am "Adding a nice new feature"`)
4. Push to the branch (`git push origin my_new_feature`)
5. Open a Pull Request with relevant information
