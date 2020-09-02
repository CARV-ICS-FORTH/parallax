#!/bin/bash
set -e
#git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@carvgit.ics.forth.gr/evolve/kreon.git -b ${CI_BUILD_REF_NAME} kreon-pre-commit
#cd kreon-pre-commit
FILES=$(git diff-tree --no-commit-id --name-only -r "$CI_COMMIT_SHA" | awk '$1=$1' ORS=' ')
echo "$FILES"

for i in $FILES; do
	echo ""
	echo "$i "
	pre-commit run --files "$i"
	echo ""
done
