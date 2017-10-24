#!/bin/bash
set -eou pipefail
AUTOTAG_URL=${AUTOTAG_URL:-}

# ensure we have autotag
if [ ! -d "$HOME/bin" ]; then
  mkdir -p ~/bin
fi

if [ ! -f "$HOME/bin/autotag" ]; then
  AUTOTAG_URL=$(curl -silent -o - -L https://api.github.com/repos/pantheon-systems/autotag/releases/latest | grep 'browser_' | grep 'Linux' | cut -d\" -f4 | awk '{print $0}')
  # handle the off chance that this wont work with some pre-set version
  if [ -z "$AUTOTAG_URL" ] ;  then
    AUTOTAG_URL="https://github.com/pantheon-systems/autotag/releases/download/v0.0.3/autotag.linux.x86_64"
  fi
  echo "Pulling $AUTOTAG_URL"
  curl -sf -L $AUTOTAG_URL -o ~/bin/autotag > /dev/null
  chmod 755 ~/bin/autotag
fi

if ! grep -q 'email' ~/.gitconfig ; then
  git config --global user.email "infrastructure+circleci@getpantheon.com"
  git config --global user.name "CI"
fi


GITSHA=$(git log -1 --format="%h")

function gittag {
  git tag -a v$VERSION -m "auto release $VERSION" # one day we will parse metadata and add deps here
  git push origin --tags
}

BUILD=$CIRCLE_BUILD_NUM
if [ -z "$CIRCLE_BUILD_NUM" ] ; then
  BUILD=0
fi

# tag/autoversion and write out metadata
TAG=$(~/bin/autotag -n)
VERSION=${TAG}+${BUILD}

# push
case $CIRCLE_BRANCH in
"master")
  CHANNEL="release"
  gittag
  ;;
"stage")
  CHANNEL="stage"
  ;;
"yolo")
  CHANNEL="yolo"
  ;;
*)
  CHANNEL="dev"
  ;;
esac

echo $CHANNEL > CHANNEL
echo $VERSION > VERSION
