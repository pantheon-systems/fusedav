#!/bin/bash
set -e
bin="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
docker=$(which docker)

# which fedora distros to build this rpm for
BUILD_VERSIONS=${BUILD_VERSIONS:-22 28}

echo "==> Running RPM builds for these Fedora version(s): $BUILD_VERSIONS"

RUN_ARGS="--rm"

# set a default build -> 0 for when it doesn't exist
CIRCLE_BUILD_NUM=${CIRCLE_BUILD_NUM:-0}

DEVEL=${DEVEL:-}

# location to mount the source in the container
inner_mount="/fusedav"

echo "==> Creating docker volume for fusedav files"
$docker volume create fusedav_vol
$docker run --name cp-vol -v fusedav_vol:/fusedav busybox true
$docker cp $bin/../. cp-vol:/fusedav/

docker login -p "$QUAY_PASSWD" -u "$QUAY_USER" quay.io

# epoch to use for -revision
epoch=$(date +%s)

for ver in $BUILD_VERSIONS; do
    echo "==> Building rpm for fedora $ver "

    build_image=quay.io/getpantheon/rpmbuild-fusedav:${ver}
    $docker pull $build_image

    channel=$(tr -d "\n\r" < $bin/../CHANNEL)
    exec_cmd="$inner_mount/scripts/docker-inner.sh $channel$DEVEL $inner_mount/pkg $CIRCLE_BUILD_NUM $epoch"
    if [ -n "$BUILD_DEBUG" ] ; then
      RUN_ARGS="$RUN_ARGS -ti "
      exec_cmd="/bin/bash"
    fi

    read docker_cmd <<-EOL
      $docker run $RUN_ARGS \
        -e "build=$CIRCLE_BUILD_NUM" \
        -w $inner_mount \
        -v fusedav_vol:$inner_mount \
        $build_image $exec_cmd
EOL

    echo "Running: $docker_cmd"
    $docker_cmd

    echo "copying the rpm from the container..."
    mkdir -p "$bin/../pkg"
    $docker cp "cp-vol:/fusedav/pkg/${ver}/fusedav" "$bin/../pkg/fusedav"
    docker_tag="quay.io/getpantheon/fusedav:f${ver}-${CIRCLE_BUILD_NUM}${DEVEL}"
    docker_build="$docker build -t $docker_tag --build-arg VERSION=${ver} ."

    echo "Running: $docker_build"
    $docker_build

    docker_push="$docker push $docker_tag"

    echo "Running: $docker_push"
    $docker_push

done

$docker rm cp-vol
$docker volume rm fusedav_vol
