#!/usr/bin/env bash
set -euo pipefail
pip install -U pip
pip install gitlint

for commit in $(git rev-parse "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"..."$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME" | sed '$d'); do
	commit_msg=$(git log -1 --pretty=%B "$commit")
	echo "$commit"
	echo "$commit_msg" | gitlint
	echo "--------"
done
