#!/bin/bash

if [ $# -ne 2 ]; then
	echo 'Usage: mkfs.sh <device name> <type of volume (0 for device 1 for file)>'
	exit 1
fi

INSIDE_BUILD_DIR=../lib/mkfs.parallax
BUILD_PATH=../build/lib/mkfs.parallax
SYSTEM_PATH=/usr/local/bin/mkfs.parallax

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
TYPE_OF_VOLUME=$2

if [ "$TYPE_OF_VOLUME" -le 0 ]; then
	DEV_SIZE=$(blockdev --getsize64 "${DEV_NAME}")
elif [ "$TYPE_OF_VOLUME" -le 1 ]; then
	DEV_SIZE=$(wc -c <"$DEV_NAME")
else
	echo "unknown type of volume"
	exit
fi

echo 'Device:' "${DEV_NAME}" 'has size' "${DEV_SIZE}" 'bytes'
echo 'Allocator size:' "${DEV_SIZE}"

OFFSET=0
${MKFS} "${DEV_NAME}" "${OFFSET}" "${DEV_SIZE}" >/dev/null
exit 0
