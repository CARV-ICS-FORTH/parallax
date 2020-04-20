#!/bin/bash

#  sudo chown gesalous /dev/fbd
if [ $# -ne 3 ]; then
	echo 'Usage: mkfs.eutropia.single.sh <device name> <number of DBs> <type of volume (0 for device 1 for file)>'
	exit 1
fi

INSIDE_BUILD_DIR=../kreon_lib/mkfs.kreon
BUILD_PATH=../build/kreon_lib/mkfs.kreon
SYSTEM_PATH=/usr/local/bin/mkfs.kreon

if [ -f "$INSIDE_BUILD_DIR" ]; then
	echo "Executable chosen $INSIDE_BUILD_DIR"
	MKFS_KREON=$INSIDE_BUILD_DIR
elif [ -f "$BUILD_PATH" ]; then
	echo "Executable chosen $BUILD_PATH"
	MKFS_KREON=$BUILD_PATH
else
	echo "System Path $SYSTEM_PATH executable chosen"
	MKFS_KREON=$SYSTEM_PATH
fi

DEV_NAME=$1
DB_NUM=$2
TYPE_OF_VOLUME=$3
if [ "$DB_NUM" -le 0 ]; then
	echo 'DB number cannot be less than 1!'
	exit 1
fi

if [ "$TYPE_OF_VOLUME" -le 0 ]; then
	DEV_SIZE=$(blockdev --getsize64 "${DEV_NAME}")
elif [ "$TYPE_OF_VOLUME" -le 1 ]; then
	DEV_SIZE=$(wc -c <"$DEV_NAME")
else
	echo "unknown type of volume"
	exit
fi

ALLOCATOR_SIZE=$((DEV_SIZE / DB_NUM))

echo 'Device:' "${DEV_NAME}" 'has size' "${DEV_SIZE}" 'bytes'
echo 'Allocator size:' "${ALLOCATOR_SIZE}"

for i in $(seq 0 $((DB_NUM - 1))); do
	OFFSET=$( (${i} \* ALLOCATOR_SIZE))
	${MKFS_KREON} "${DEV_NAME}" "${OFFSET}" "${ALLOCATOR_SIZE}" >/dev/null
done
exit 0
