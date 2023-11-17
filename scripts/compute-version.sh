#!/bin/bash
#
# compute-version.sh generates version strings and image tags.
#
# See end of this file for format specifics, including examples.
#
# When run from GitHub Actions, the GITHUB_* variables will be used.
#
# When run locally (perhaps within a dev container), the GITHUB_* variables
# are not available, but `.git/` should exist so we can get the necessary
# information ourselves.
#
set -eou pipefail

if [ -n "${REGISTRY:-}" ] ; then
  IMAGE_REPOSITORY="${REGISTRY}/${IMAGE_NAME:-fusedav}"
else
  # if no REGISTRY, build image for local use
  IMAGE_REPOSITORY="${IMAGE_NAME:-fusedav}"
fi

# Ensure we have autotag.
if ! command -v autotag > /dev/null ; then
  echo "autotag is not available; aborting" > /dev/stderr
  exit 1
fi

# Ensure we have build_num.
build_num=${GITHUB_RUN_NUMBER:-}
if [ -z "$build_num" ] ; then
  echo "GITHUB_RUN_NUMBER not set, assuming '1'" > /dev/stderr
  build_num=1
fi

# Ensure we have branch name.
raw_branch=${GITHUB_REF_NAME:-}
if [ -z "${raw_branch}" ] ; then
  echo "GITHUB_REF_NAME not set, extracting from git directly" > /dev/stderr
  raw_branch=$(git rev-parse --abbrev-ref HEAD)
fi

# Sanitize branch name.
#
# Yes, this is overly restrictive.  The git rules for naming branches are
# quite complex.
# https://git-scm.com/docs/git-check-ref-format
safe_branch=$(sed -e 's/[^0-9A-Za-z-]/-/g' <<<$raw_branch)

# Ensure we have git commit hash.
if [ -n "${GITHUB_SHA:-}" ]; then
  git_commit="$(echo $GITHUB_SHA | cut -c -7)"
else
  echo "GITHUB_SHA not set, extracting from git directly" > /dev/stderr
  git_commit="$(git rev-parse --short HEAD)"
  if [ -n "$(git status --porcelain)" ] ; then
    git_commit="${git_commit}-dirty"
  fi
fi

# Compute new SemVer string and image tag(s).
#
# $raw_branch is being directly appended in some places to avoid shell
# interpolation issues.
# (Example: Consider a branch name which contains a single quote, double
# quote, and/or semicolon.)
IMAGE_TAGS=( "${IMAGE_REPOSITORY}:${build_num}-"$safe_branch )
if [ "${safe_branch}" == "main" -o "${safe_branch}" == "master" ] ; then
  full_semver="$(autotag -n -m "${build_num}.${git_commit}" -b $raw_branch)"

  # Originally, the actual `vN.N.N` git release tag was created by this
  # invocation of autotag.  However, `gh` appears to do that on its own
  # when creating a release, so we now include `-n` here to suppress
  # the generation of a potentially confusing/conflicting git tag.
  bare_ver="$(autotag -n -b $raw_branch)"

  GITHUB_RELEASE_NAME="v${bare_ver}"
  rpm_ver=$bare_ver

  # When main/master, also create SemVer tag.
  IMAGE_TAGS+=( "${IMAGE_REPOSITORY}:${bare_ver}" )
else
  full_semver="$(autotag -n -p "${safe_branch}.${build_num}" -m $git_commit -b $raw_branch)"
  bare_ver=$(autotag -n -b $raw_branch)
  GITHUB_RELEASE_NAME="v$(autotag -n -p "${safe_branch}.${build_num}" -b $raw_branch)"
  rpm_ver="${bare_ver}~${safe_branch}"
fi

# In the examples below:
#   - latest tag on the git repo is v0.0.1.
#   - GITHUB_REF_NAME is fix-bug.
#   - GITHUB_RUN_NUMBER is 3.
#   - GITHUB_SHA is abc1234fffff.

# iff main/master: v0.0.2
#            else: v0.0.2-fix-bug.3
echo "export GITHUB_RELEASE_NAME=${GITHUB_RELEASE_NAME}"

# image tag(s) to be pushed to registry/repository
#   - always: ...:3-fix-bug
#   - iff main/master: also ...:0.0.2
echo "export IMAGE_TAGS=( ${IMAGE_TAGS[@]} )" # keep args separate

# iff main/master: 0.0.2+3.abc1234
#            else: 0.0.2-fix-bug.3+abc1234
echo "export SEMVER=${full_semver}"

# iff main/master: RPM_VERSION=0.0.2         RPM_RELEASE=1
#            else: RPM_VERSION=0.0.2~fix_bug RPM_RELEASE=1
#
# Originally, we set RPM_RELEASE to $build_num; it is unclear if this is
# useful or merely distracting.
echo "export RPM_VERSION=${rpm_ver//-/_}"
echo "export RPM_RELEASE=1"
