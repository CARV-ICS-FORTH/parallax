#!/usr/bin/env bash

ARGS=""
for item in "${@:2}"; do
	ARGS+=" $item"
done

TEST_NAME="$1"

# Parse the filename from the arguments, we match the =filename pattern and then we omit the = and match only the filename.
FILENAME=$(echo "$ARGS" | grep -o "\--file=[^ ]*" | grep -oE '=\S+')
FILENAME="${FILENAME:1}"

DIRECTORY_NAME=$(dirname "$FILENAME")

if [[ "$DIRECTORY_NAME" != "." ]]; then
	mkdir -p "$DIRECTORY_NAME"
fi

fallocate -l 16G "$FILENAME"

#Leaving this here for the tests to pass, in the next PR it will be deleted
./mkfs.sh "$FILENAME" 128
# We either run YCSB or small tests. In the case of YCSB we need to provide specific arguments in a specific order to the run-ycsb.sh.
if [[ "$TEST_NAME" == *"run-ycsb.sh"* ]]; then
	# Disabling the warning here intentionally, otherwise the executable cannot receive the command line arguments as expected.
	# shellcheck disable=SC2086
	bash "$TEST_NAME" "$FILENAME" $ARGS
	EXIT_CODE=$?
else
	# Disabling the warning here intentionally, otherwise the executable cannot receive the command line arguments as expected.
	# shellcheck disable=SC2086
	./"$TEST_NAME" $ARGS
	EXIT_CODE=$?
fi

rm -f "$FILENAME"
exit $EXIT_CODE
