#!/bin/bash
pip install -U pip
pip install pre-commit
#git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@carvgit.ics.forth.gr/evolve/kreon.git -b ${CI_BUILD_REF_NAME} kreon-pre-commit
#cd kreon-pre-commit
FILES=`git diff-tree --no-commit-id --name-only -r $CI_COMMIT_SHA`
pre-commit run --files `echo $FILES`
