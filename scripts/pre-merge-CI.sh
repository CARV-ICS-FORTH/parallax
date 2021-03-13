#!/bin/bash
set -e
pip install gitlint
FILES=$(git --no-pager diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --name-only)
echo "$FILES"
for i in $FILES; do
	echo ""
	echo "$i "
	SKIP=protect-first-parent pre-commit run --files "$i"
	echo ""
done
