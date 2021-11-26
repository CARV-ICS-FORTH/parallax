#!/bin/bash

if [ $# -ne 2 ]; then
	echo 'Usage: mkfs.sh <device name> <max number of regions to host>'
	exit 1
fi

INSIDE_BUILD_DIR=../lib/kv_format.parallax
BUILD_PATH=../build/lib/kv_format.parallax
SYSTEM_PATH=/usr/local/bin/kv_format.parallax

if [ -f "$INSIDE_BUILD_DIR" ]; then
	echo "Executable chosen $INSIDE_BUILD_DIR"
	MKFS=$INSIDE_BUILD_DIR
elif [ -f "$BUILD_PATH" ]; then
	echo "Executable chosen $BUILD_PATH"
	MKFS=$BUILD_PATH
else
	echo "System Path $SYSTEM_PATH executable chosen"
	MKFS=$SYSTEM_PATH
fi

cp options.yml "$(dirname "${MKFS}")"

DEV_NAME=$1
NUMBER_OF_REGIONS=$2

${MKFS} --device "${DEV_NAME}" --max_regions_num "${NUMBER_OF_REGIONS}" >/dev/null
exit 0
