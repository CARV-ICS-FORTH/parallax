#!/usr/bin/env bash
set -exvpipefail

declare -a KV_MIX=("s" "m" "l" "sd" "md" "ld")
readonly FILE=/tmp/kv_store.dat
readonly NUM_OF_KVS=4000000
readonly SCAN_SIZE=30
readonly WORKLOAD="All"

for curr_kv_mix in "${KV_MIX[@]}"; do
	echo "Running workload $curr_kv_mix back to back!"
	./mkfs.sh "$FILE" 128
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="$WORKLOAD" --kv_mix="$curr_kv_mix"
done

for curr_kv_mix in "${KV_MIX[@]}"; do
	echo "Running workload $curr_kv_mix with par_close!"
	./mkfs.sh "$FILE" 128
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Load" --kv_mix="$curr_kv_mix"
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Get" --kv_mix="$curr_kv_mix"
	./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Scan" --kv_mix="$curr_kv_mix"
done
