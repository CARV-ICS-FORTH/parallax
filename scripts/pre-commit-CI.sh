#!/bin/bash
set -e
pip install gitlint

FILES=$(git diff-tree --no-commit-id --name-only -r "$CI_COMMIT_SHA" | awk '$1=$1' ORS=' ')
echo "$FILES"
for i in $FILES; do
	echo ""
	echo "$i "
	SKIP=protect-first-parent pre-commit run --files "$i"
	echo ""
done

gitlint
