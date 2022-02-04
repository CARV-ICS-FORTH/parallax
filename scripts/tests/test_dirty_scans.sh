#!/usr/bin/env bash
set -exvpipefail

declare -a KV_MIX=("s" "m" "l" "sd" "md" "ld")
readonly FILE=/tmp/kv_store.dat
readonly NUM_OF_KVS=4000000
readonly SCAN_SIZE=30
WORKLOAD="All"

for i in "${KV_MIX[@]}"; do
	echo "Running workload $i back to back!"
	./mkfs.sh "$FILE" 128
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="$WORKLOAD" --kv_mix="$i"
done

for i in "${KV_MIX[@]}"; do
	echo "Running workload $i with par_close!"
	./mkfs.sh "$FILE" 128
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Load" --kv_mix="$i"
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Get" --kv_mix="$i"
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Scan" --kv_mix="$i"
done
