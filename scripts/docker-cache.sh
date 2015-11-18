#!/bin/bash
set -e
tags=(20 22)

docker=$(which docker)
if [ -n "$docker" ] ; then
  if [ -f "/usr/bin/docker" ] ; then
    docker="/usr/bin/docker"
  else
    echo "No docker executable found :("
    exit 1
  fi
fi

if [  ! -d $HOME/docker ] ; then
  mkdir -p $HOME/docker
fi

for i in $tags ; do
  img_tar="$HOME/docker/fusedav-${i}.tar"
  if [ -f $img_tar ] ; then
    $docker load -i $img_tar
  else
    curl -L -f https://quay.io/c1/squash/getpantheon/rpmbuild-fusedav/$i | docker load
    $docker save -o $img_tar "quay.io/getpantheon/rpmbuild-fusedav:${i}.squash"
  fi
done
