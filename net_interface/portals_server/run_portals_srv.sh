#!/bin/bash

OUTPUT_DIR="./results"
dir_results="${OUTPUT_DIR}"
NETWORK_INTERFACE="ens10d1.905"
NUM_THREAD=32

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

get_network_stats() {
	local interface=$1
	grep "$interface" /proc/net/dev | awk '{print $2, $10}' # RX bytes, TX bytes
}

start_stats() {
	start_time=$(date +%s)
	echo "$start_time" >"${dir_results}/start_time"
	initial_stats=$(get_network_stats "$NETWORK_INTERFACE")
	echo "$initial_stats" >"${dir_results}/network_initial.txt"

	iostat 1 >"${dir_results}/iostat.txt" &
	IOSTAT_PID=$!
	mpstat 1 >"${dir_results}/mpstat.txt" &
	MPSTAT_PID=$!
	cat /proc/diskstats >"${dir_results}/diskstats-before.txt"
}

stop_stats() {
	end_time=$(date +%s)
	echo "$end_time" >"${dir_results}/end_time"
	final_stats=$(get_network_stats "$NETWORK_INTERFACE")
	echo "$final_stats" >"${dir_results}/network_final.txt"

	if ps -p $IOSTAT_PID >/dev/null 2>&1; then
		kill -9 $IOSTAT_PID
	fi

	if ps -p $MPSTAT_PID >/dev/null 2>&1; then
		kill -9 $MPSTAT_PID
	fi

	cat /proc/diskstats >"${dir_results}/diskstats-after.txt"
}

calculate_throughput() {
	local rx_bytes_initial=$1
	local tx_bytes_initial=$2
	local rx_bytes_final=$3
	local tx_bytes_final=$4
	local duration=$5

	if [ -z "$duration" ] || [ "$duration" -le 0 ]; then
		echo "Error: Invalid duration for throughput calculation."
		return 1
	fi

	local rx_bytes_diff=$((rx_bytes_final - rx_bytes_initial))
	local tx_bytes_diff=$((tx_bytes_final - tx_bytes_initial))

	local rx_throughput
	rx_throughput=$(awk "BEGIN {print $rx_bytes_diff / $duration / 1024 / 1024}")

	local tx_throughput
	tx_throughput=$(awk "BEGIN {print $tx_bytes_diff / $duration / 1024 / 1024}")

	echo "Average RX Throughput: $rx_throughput MB/s"
	echo "Average TX Throughput: $tx_throughput MB/s"
}

cleanup() {
	echo "Stopping server..."
	pkill -f "portals_parallax_server"
	echo "Stopping monitoring..."
	stop_stats

	read -r rx_bytes_initial tx_bytes_initial <"${dir_results}/network_initial.txt"
	read -r rx_bytes_final tx_bytes_final <"${dir_results}/network_final.txt"

	start_time=$(cat "${dir_results}/start_time")
	end_time=$(cat "${dir_results}/end_time")
	duration=$((end_time - start_time))

	calculate_throughput "$rx_bytes_initial" "$tx_bytes_initial" "$rx_bytes_final" "$tx_bytes_final" $duration

	exit
}
rm -rf out.txt

# Trap Ctrl+C
trap cleanup SIGINT

start_stats

echo "Starting server..."
./portals_parallax_server -t $NUM_THREAD -f /app/par.dat -L0 4 -GF 4 -pf >out.txt 2>&1 &
SERVER_PID=$!

echo "Server running... Press Ctrl+C to stop."
wait "$SERVER_PID"

cleanup
