# Fusedav

[![Unsupported](https://img.shields.io/badge/Pantheon-Unsupported-yellow?logo=pantheon&color=FFDC28)](https://pantheon.io/docs/oss-support-levels#unsupported)

## Fusedav Client

This is a fuse-based DAV client with extensions for performance.
This will run against any standard DAV implementation, i.e.
`pywebdav` (see tests).

## Production (CI/CD) Build

Merging anything to the `master` branch will trigger GitHub Actions to build
a production release.

The RPM(s) are published as a [Release](https://github.com/pantheon-systems/fusedav/releases).

Container image(s) are published as [Packages](https://github.com/pantheon-systems/fusedav/pkgs/container/fusedav).
Images are generally accessed as `ghcr.io/pantheon-systems/fusedav:0.0.0`, where
`0.0.0` is the desired version.

### RPM Retrieval / Installation

Note that, while the RPM version is removed from the filename entirely, the
RPM release `.fc28` suffix is retained.  This is being done to allow for use
of other base images/distributions in the future.

```sh
# Install latest release
curl -fsSL https://github.com/pantheon-systems/fusedav/releases/latest/download/fusedav.fc28.x86_64.rpm \
    -o fusedav.x86_64.rpm \
  && dnf install -y fusedav.x86_64.rpm
  
# Install specific release
RELEASE_NAME=v0.0.0-branch.1
curl -fsSL "https://github.com/pantheon-systems/fusedav/releases/download/${RELEASE_NAME}/fusedav.fc28.x86_64.rpm" \
    -o fusedav.x86_64.rpm \
  && dnf install -y fusedav.x86_64.rpm
  
# Install specific release, alternate method
RELEASE_NAME=v0.0.0-branch.1
curl -fsSL "https://api.github.com/repos/pantheon-systems/fusedav/releases/tags/${RELEASE_NAME}" \
  | jq ".assets[] | select(.name==\"fusedav.fc28.x86_64.rpm\") | .browser_download_url" \
  | xargs curl -o fusedav.x86_64.rpm -fsSL \
  && dnf install -y fusedav.x86_64.rpm
```

## Development Build

### Development Image Build

Building a local container image requires only:

1) a local Docker (or Podman) installation, and
1) [autotag](https://github.com/pantheon-systems/autotag) in the PATH.
PATH.

```sh
scripts/compute-version.sh | tee new-version.sh
docker build --progress plain -t fusedav .
```

### Development RPM Build

Building a set of RPMs within a containerized environment requires only:

1) a local Docker (or Podman) installation, and
1) [autotag](https://github.com/pantheon-systems/autotag) in the PATH.

The generated RPMs will be written to the `extract` directory.

```sh
scripts/compute-version.sh | tee new-version.sh
docker build --progress plain --target extract . --output=extract
```

### Development Code Build

1. Clone the git repository.
    - You may have done this already.
    - `git clone git://github.com/pantheon-systems/fusedav.git`
1. Install build dependencies.
    - See `BuildRequires` in [fusedav-template.spec](fusedav-template.spec)
        for required Fedora Linux 28 packages.
    - You may have done this already.
    - ALTERNATIVELY, open this git repository in Visual Studio Code with
        the [ms-vscode-remote.remote-containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
        extension active and work within the `fedora28` (default) dev
        container.
1. Compile the code.
    - `git clean -f -x -d && ./autogen.sh && ./configure && make`
    - The executable will be written to `src/fusedav`.

## Usage

Use the `-V` flag to see libraries.

```text
$ src/fusedav -V
fusedav version 2.0.42-bccf93b
LevelDB version 1.20
libcurl/7.59.0 OpenSSL/1.1.0i zlib/1.2.11 libidn2/2.0.5 libpsl/0.20.2 (+libidn2/2.0.4) libssh/0.8.5/openssl/zlib nghttp2/1.32.1
FUSE library version: 2.9.7
```

## libcurl and OpenSSL

FuseDAV requires libcurl linked with OpenSSL. On Fedora versions before 27 the
provided libcurl is linked against NSS and you need to provide your own libcurl
linked against OpenSSL.

## Contributing

1. Fork it.
2. Create a branch (`git checkout -b my_new_features`).
3. Commit your changes (`git commit -am "Adding a nice new feature"`).
4. Push to the branch (`git push origin my_new_feature`).
5. Open a Pull Request with relevant information.
