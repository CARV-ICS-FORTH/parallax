#!/bin/bash
set -e
pip install -U pip
pip install pre-commit
FILES=$(git --no-pager diff origin/"$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --name-only)
echo "$FILES"

for i in $FILES; do
	echo ""
	echo "$i "
	pre-commit run --files "$i"
	echo ""
done
