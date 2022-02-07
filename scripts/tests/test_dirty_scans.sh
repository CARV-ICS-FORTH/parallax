#!/usr/bin/env bash
set -exvpipefail

KV_MIX="$1"
readonly FILE=/tmp/kv_store.dat
readonly NUM_OF_KVS=4000000
readonly SCAN_SIZE=30

echo "Running workload $KV_MIX with par_close!"
./mkfs.sh "$FILE" 128
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Load" --kv_mix="$KV_MIX"
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Get" --kv_mix="$KV_MIX"
./test_dirty_scans --file="$FILE" --num_of_kvs="$NUM_OF_KVS" --scan_size="$SCAN_SIZE" --workload="Scan" --kv_mix="$KV_MIX"
