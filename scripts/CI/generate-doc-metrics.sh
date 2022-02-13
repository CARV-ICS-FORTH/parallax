#!/usr/bin/env bash
set -xe

# Clone master branch in /tmp and compare its documentation with the current branch
PWD=$(pwd)
cd /tmp
git clone https://gitlab-ci-token:"${CI_JOB_TOKEN}"@carvgit.ics.forth.gr/storage/parallax.git
cd "$PWD"

# Corner case until this branch goes into master then it will be removed
if [ ! -f "/tmp/parallax/Doxygen" ]; then
	echo "Branch $CI_DEFAULT_BRANCH does not contain a doxygen configuration!"
	exit 0
fi

./scripts/CI/coverxygen.py "$CI_COMMIT_BRANCH" . "$CI_DEFAULT_BRANCH" /tmp/parallax
