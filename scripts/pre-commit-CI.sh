#!/bin/bash
set -e
pip install gitlint
#git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@carvgit.ics.forth.gr/evolve/kreon.git -b ${CI_BUILD_REF_NAME} kreon-pre-commit
#cd kreon-pre-commit
FILES=$(git diff-tree --no-commit-id --name-only -r "$CI_COMMIT_SHA" | awk '$1=$1' ORS=' ')
echo "$FILES"
for i in $FILES; do
	echo ""
	echo "$i "
	SKIP=protect-first-parent pre-commit run --files "$i"
	echo ""
done

gitlint
