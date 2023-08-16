# fusedav uses a multi-stage image build process.
#
# base adds some basic packages to fedora:28.  It is separate to allow
# layer caching to operate.
#
# dev includes the compiler and development libraries.  It is the terminal
# stage used when running a Dev Container.
#
# compile executes the actual compile operation.
#
# extract builds an image containing only the RPM.
# By exporting that layer (BuildKit feature), we are able to access the RPM
# from the host for later publishing.
#
# runtime is the final runtime image.
#
# To build image locally:
#   docker build --progress plain --build-arg CIRCLE_SHA1=$(git rev-parse --short HEAD) -t fusedav .
#
# To compile/build and extract the RPM into the `extract` directory:
#   docker build --progress plain --build-arg GITHUB_SHA=$(git rev-parse --short HEAD) --target extract -t fusedav-extract . --output=extract
#
FROM docker.io/library/fedora:28 AS base

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN \
  dnf install -y \
    fuse \
    fuse-libs \
    jemalloc \
    leveldb \
    sudo \
    uriparser \
    which \
  && dnf clean all \
  && rm -rf /var/cache/dnf \
  && groupadd -g 1098 fusedav \
  && useradd -u 1098 -g 1098 -G wheel -d /home/fusedav -s /bin/bash -m fusedav \
  && groupadd -g 1099 vscode \
  && useradd -u 1099 -g 1099 -G wheel -d /home/vscode -s /bin/bash -m vscode \
  && echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel \
  && grep -E -q '^user_allow_other' /etc/fuse.conf || echo user_allow_other >> /etc/fuse.conf

# TODO: consider removing fusedav from wheel group

########################################

FROM base AS dev

RUN \
  dnf install -y \
    autoconf \
    automake \
    bind-utils \
    expat-devel \
    findutils \
    fuse-devel \
    gcc \
    gdb \
    git \
    glib2-devel \
    jemalloc-devel \
    leveldb-devel \
    libcurl-devel \
    make \
    procps-ng \
    rpm-build \
    ruby-devel \
    strace \
    systemd-devel \
    tcpdump \
    uriparser-devel \
    zlib-devel \
  && dnf clean all \
  && rm -rf /var/cache/dnf \
  && gem install fpm --no-rdoc --no-ri \
  && gem install package_cloud -v 0.2.45 \
  && curl -fsSL https://github.com/pantheon-systems/autotag/releases/latest/download/autotag_linux_amd64 \
    -o /usr/local/bin/autotag \
  && chmod 0755 /usr/local/bin/autotag

# Installing autotag above makes it available within a dev container.
# When building via CI/CD, autotag is installed/called elsewhere.

USER vscode

########################################

FROM dev AS compile

COPY . /build
WORKDIR /build

ARG CIRCLE_BRANCH="unknown"
ARG CIRCLE_BUILD_NUM=""
ARG CIRCLE_SHA1=0000000

# CHANNEL is always `release` now.
# Historically, CHANNEL could be: dev, stage, yolo, release
ARG CHANNEL=release

# Set PACKAGECLOUD_REPO to `internal` or `internal-staging` to publish RPM.
ARG PACKAGECLOUD_REPO=""

# RPM_VERSION is set here for local/direct `docker build` use; CircleCI builds
# will set their own value.
ARG RPM_VERSION="0.0.0+0"

# SEMVER is set here for local/direct `docker build` use; CircleCI builds
# will set their own value.
ARG SEMVER="0.0.0-local"

RUN \
  sudo chown -R vscode /build \
  && echo "${RPM_VERSION}" > VERSION \
  && scripts/build-rpm.sh "${CHANNEL}" \
  && if [ -n "${PACKAGECLOUD_REPO}" ] ; then \
      echo SKIPPING scripts/push_packagecloud.sh ; \
    else \
      echo "NOT pushing RPM to Packagecloud as this is a pre-release build" ; \
    fi

########################################

FROM scratch AS extract

COPY --from=compile /build/pkg pkg

########################################

FROM base AS runtime

ARG CHANNEL=release

COPY --from=compile /build/src/fusedav "/opt/pantheon/fusedav-${CHANNEL}/fusedav-${CHANNEL}"
COPY scripts/exec_wrapper/mount.fusedav_chan "/usr/sbin/mount.fusedav-${CHANNEL}"

USER fusedav
