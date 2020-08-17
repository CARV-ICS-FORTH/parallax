# Setup Development Environment

## Install shfmt

To install shfmt run the command below in your shell:

	GO111MODULE=on go get mvdan.cc/sh/v3/cmd/shfmt

## Development in cluster

For development in the cluster source the script to get the latest tools:

	source kreon/scripts/devel-tools/env-vars.sh

You need to source this script when you login in a machine to develop.
If you want to avoid sourcing you could copy the contents of the script in your .bashrc.

## Pre commit hooks using pre-commit

To install pre-commit:

	pip3 install pre-commit --user
	pre-commit --version
	2.2.0

If the above command does not print a version > 2.2.0 you need to update python using:

	sudo yum update python3

Then try upgrading pre-commit:

	pip3 install -U pre-commit --user

To install pre-commit hooks:

	cd kreon
	pre-commit install
    pre-commit install --hook-type commit-msg


If everything worked as it should then the following message should be printed:

    pre-commit installed at .git/hooks/pre-commit

If you want to run a specific hook with a specific file run:

	pre-commit run hook-id --files filename
	pre-commit run cmake-format --files CMakeLists.txt


## Commit message template

	git config commit.template .git-commit-template

## Generating compile_commands.json for Single Node Kreon

Install compdb for header awareness in compile_commands.json:

	pip3 install --user git+https://github.com/Sarcasm/compdb.git#egg=compdb

After running cmake .. in the build directory run:

	cd ..
	compdb -p build/ list > compile_commands.json
	mv compile_commands.json build
	cd kreon
	ln -sf ../build/compile_commands.json


## Static Analyzer

Install the clang static analyzer with the command:

	sudo pip3 install scan-build

Before running the analyzer, make sure to delete any object files and
executables from previous build by running in the root of the repository:

	rm -r build

Then generate a report using:

	scan-build --intercept-first make

The last line of the above command's output will mention the folder where the
newly created report resides in. For example:

	"scan-build: Run 'scan-view /tmp/scan-build-2018-09-05-16-21-31-978968-9HK0UO'
	to examine bug reports."

To view the report you can run the above command, assuming you have a graphical
environment or just copy the folder mentioned to a computer that does and open
the index.html file in that folder.
