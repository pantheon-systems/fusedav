Fusedav CI/CD
-------------
The scripts herein are invoked by CircleCI via the circle.yml. They use docker containers to build and package Fusedav for our target platforms (fedora 20/22).

## Environment Variables
* CIRCLE_BUILD_NUM - Used to determine the build iterator. Defaults to 0 if not present
* BUILD_VERSIONS - a shell array of fedora versions to build for. Defaults to (20 22)
* BUILD_DEBUG - If present triggers the build scripts to drop you into a shell for the docker container.

## Local building of dev packages
Building local is simple, first invoke the version.sh to generate the VERSION and CHANNEL files, and call docker-outter.sh. This assumes you have a working docker setup.

```
  ./scripts/version.sh
  ./scripts/docker-outer.sh
```

## Debuging Builds
To get a shell in a docker build container use `BUILD_DEBUG=1` `BUILD_VERSIONS` and invoke `docker-outter.sh`

```
BUILD_DEBUG=1 BUILD_VERSIONS=22 ./scripts/docker-outer.sh
==> Running RPM builds for these Fedora version(s): 22
==> Building rpm for fedora 22
....
[root@144a1b05fb05 src]# cat /etc/redhat-release
Fedora release 22 (Twenty Two)
```

## Scripts
### version.sh
This will build a VERSION file and CHANNEL file in the root of the project. The autoconf and CI scripts utilize these files for building and for packaging.

This file is ignored by git, because build-time controls their creation

### docker-outer.sh
This script is the main outer execution loop. It loops over our desired platforms and executes docker in that environment. The script will mounting the source directory into the docker container for building, and execute `docer-inner.sh` inside the container.

If you want to get into a container for debugging you can export BUILD_DEBUG with any value to be dropped into an interactive shell on the docker container.

```
╭─jnelson@prefect ~/panth/fusedav  ‹rpmbuild*›
╰─➤  BUILD_DEBUG=1 ./scripts/docker-outer.sh
==> Running RPM builds for these Fedora version(s): 20 22
==> Building rpm for fedora 20
20: Pulling from getpantheon/rpmbuild-fusedav
70568946e5cd: Already exists
03dc8acc8238: Already exists
...
Digest: sha256:b0f4562429925a8be579eb7b86fea8fe8e676b7a962bba8d6bf372fb68b396d7
Status: Image is up to date for quay.io/getpantheon/rpmbuild-fusedav:20
Running: docker run --rm -ti          -e "build=0"         -w /src         -v /Users/jnelson/orgs/pantheon/fusedav/scripts/../:/src         quay.io/getpantheon/rpmbuild-fusedav:20  /bin/bash
[root@d868541bc6ae src]#
```

### docker-inner.sh
This script is build and packaging execution for fusedav. It runs the build and sets up an rpm based on the CHANNEL file.

It accepts the arguments  `channel`, `rpm_dir`, `build_number`, `revision`. Generally this is invoked from `docker_outer.sh` but if you are debugging you can invoke it by hand from inside a build container

```
[root@d868541bc6ae src]# ./scripts/docker-inner.sh dev /src/pkg 0 0

----------------------------------------------------------------
Initialized build system. For a common configuration please run:
----------------------------------------------------------------

./configure CFLAGS='-g -O0'

checking for a BSD-compatible install... /usr/bin/install -c
checking whether build environment is sane... yes
checking for a thread-safe mkdir -p... /usr/bin/mkdir -p
...

Created package {:path=>"fusedav-dev-2.0.1+0-0.a63cceb.x86_64.rpm", :file=>"clamp/command.rb", :line=>"67", :method=>"run"}
```

### push_packagecloud.sh
This is a wrapper to push the builds up to package cloud.
Execution is controlled by branches specified in the circle.yml

It uses `BUILD_VERSIONS` env var to determine the platforms to push, and takes a single argument for the repo to push too `internal` or `internal-staging`
