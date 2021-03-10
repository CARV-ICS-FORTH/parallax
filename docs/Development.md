# Setup Development Environment

## Development in cluster

For development in the cluster source the script to get the latest tools:

	source parallax/scripts/devel-tools/env-vars.sh

You need to source this script every time you login in a machine to develop.
If you want to avoid sourcing you could copy the contents of the script in your .bashrc.

## Install shfmt

To install shfmt run the command below in your shell:

	GO111MODULE=on go get mvdan.cc/sh/v3/cmd/shfmt


## Pre commit hooks using pre-commit

To install pre-commit:

	pip3 install pre-commit --user
	pre-commit --version
	2.2.0

If the machine you are logged in does not have pip3 installed then run:

	curl https://pre-commit.com/install-local.py | python3 -

If `pre-commit --version` does not print a version > 2.2.0 you need to update/upgrade pre-commit:

	pip3 install -U pre-commit --user

To install pre-commit hooks:

	cd parallax
	pre-commit install
    pre-commit install --hook-type commit-msg

If everything worked as it should then the following message should be printed:

    pre-commit installed at .git/hooks/pre-commit

If you want to run a specific hook with a specific file run:

	pre-commit run hook-id --files filename

For example:

	pre-commit run cmake-format --files CMakeLists.txt


## Commit message template

To set up the commit template you need to run:

	cd parallax
	git config commit.template .git-commit-template

## Generating compile_commands.json for Parallax

After running cmake .. in the build directory run:

	cd parallax
	mkdir build;cd build
	cmake ..
	cd ..
	ln -sf build/compile_commands.json

If your editor requires headers in the compilation database

Install compdb that generates a compilation database with headers:

	pip3 install --user git+https://github.com/Sarcasm/compdb.git#egg=compdb

then create the compilation database by running:

	cd parallax
	compdb -p build list > compile_commands.json

## Debugging with Compiler Sanitizers

If you want to learn what compilers sanitizers are, check [Wikipedia](https://en.wikipedia.org/wiki/AddressSanitizer).

To use compiler sanitizers to debug code in this project you only need to activate when running the `cmake` command by adding `-DUSE_SANITIZER=YourSanitizer`.
For example to compile your code with the leak sanitizer:

	cmake3 .. -DUSE_SANITIZER=Leak

To see which sanitizers are supported check this [file](https://github.com/StableCoder/cmake-scripts/blob/main/sanitizers.cmake#L20).
