#!/usr/bin/env bash
set -exvpipefail
ARGS=""
for item in "${@:1}"; do
	ARGS+=" $item"
done

KV_MIX="$1"
if [[ -z "${NVME0}" ]]; then
	readonly FILEPATH="$NVME0"/"$CI_JOB_ID"
	readonly FILE="$FILEPATH"/kv_store.dat
else
	FILE=$(echo "$ARGS" | grep -o "\--file=[^ ]*" | grep -oE '=\S+')
	FILE="${FILE:1}"
	DIRECTORY_NAME=$(dirname "$FILE")
	if [[ "$DIRECTORY_NAME" != "." ]]; then
		mkdir -p "$DIRECTORY_NAME"
	fi
fi

readonly NUM_OF_KVS=1000000
readonly SCAN_SIZE=5

fallocate -l 16G "$FILE"
echo "Running workload $KV_MIX with par_close!"
mkdir -p "$FILEPATH"
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Load" --kv_mix="$KV_MIX"
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Get" --kv_mix="$KV_MIX"
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Scan" --kv_mix="$KV_MIX"
