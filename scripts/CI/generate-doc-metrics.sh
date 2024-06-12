#!/usr/bin/env bash
set -xe

if [ -d /builds/storage/"${CI_PROJECT_NAME}" ]; then
	PROJECT_BASE_DIR=storage/${CI_PROJECT_NAME}
else
	PROJECT_BASE_DIR=gxanth/${CI_PROJECT_NAME}
fi

# Clone master branch in /tmp and generate its documentation
cd /tmp
git clone https://gitlab-ci-token:"${CI_JOB_TOKEN}@carvgit.ics.forth.gr/${PROJECT_BASE_DIR}".git parallax
cd parallax
doxygen Doxyfile

# Generate documentation for current branch
cd /builds/"${PROJECT_BASE_DIR}"/
doxygen Doxyfile
python -m venv venv
source venv/bin/activate
pip install --no-cache-dir coverxygen
# Compare documentation coverage for the two branches
python3 scripts/CI/coverdocs.py "$CI_COMMIT_BRANCH" /builds/"${PROJECT_BASE_DIR}" "$CI_DEFAULT_BRANCH" /tmp/parallax
