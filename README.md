Fusedav
=======

Fusedav Client
--------------

This is a fuse-based DAV client extended for performance.
This will run against any standard DAV implementation, i.e.,
`pywebdav` (see tests).


Installation
------------

1. ```git clone git://github.com/pantheon-systems/fusedav.git```
2. ```git clean -f -x -d && ./autogen.sh && ./configure && make```

Usage
-----

Use the ```-v``` flag to see libraries.
```
$ src/fusedav -v
fusedav version 2.0.5e59b8c
LevelDB version 1.12
libcurl/7.29.0 NSS/3.15.2 zlib/1.2.7 libidn/1.26 libssh2/1.4.3
FUSE library version: 2.9.3
using FUSE kernel interface version 7.19
```


Debug/Develop
-----
Running this docker script in debug mode will build a fedora-22 container with the local source mounted inside it suitable to build fusedav.
```
BUILD_VERSIONS=22 BUILD_DEBUG=1  ./scripts/docker-outer.sh
```

Contributing
------------

1. Fork it.
2. Create a branch (`git checkout -b my_new_features`)
3. Commit your changes (`git commit -am "Adding a nice new feature"`)
4. Push to the branch (`git push origin my_new_feature`)
5. Open a Pull Request with relevant information
