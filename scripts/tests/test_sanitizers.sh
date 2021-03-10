#!/bin/bash

# This test captures test_sanitizers return code and returns success when the test fails.

if ./test_sanitizers; then
	echo -e "\e[31mCommand succeeded sanitizers don't work! \e[0m"
	exit 1
else
	echo -e "\e[32mCommand failed as expected sanitizers work! \e[0m"
	exit 0
fi
