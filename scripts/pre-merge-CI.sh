#!/bin/bash
pip install -U pip
pip install pre-commit
FILES=$(git diff --name-only -r "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"..."$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME" | awk '$1=$1' ORS=' ')
pre-commit run --files "$(printf '%s' "$FILES")"
