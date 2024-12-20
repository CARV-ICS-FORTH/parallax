#!/bin/bash

OUTPUT_DIR="./results_stats"
dir_results="${OUTPUT_DIR}"
NETWORK_INTERFACE="ens10d1.905"
NUM_PROCESSES=32
trap cleanup SIGINT

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

	# Calculate RX and TX bytes differences
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

start_stats

trap 'echo "Interrupt signal received. Killing all processes..."; kill 0; exit 1' SIGINT

cleanup_2() {
	echo "A process failed. Killing all background processes..."
	kill 0
	exit 1
}

rm -rf RESULTS/*
PIDS=()

for i in $(seq 1 $NUM_PROCESSES); do
	echo "Starting iteration $i..."

	rm -rf out.txt

	./ycsb-net -p /app/par.dat -insertStart 0 -clientProcesses 1 -stats on -o "./RESULTS/RESULTS$i/" >out.txt 2>&1 &
	PROCESS_PID=$!

	PIDS+=("$PROCESS_PID")

	if ! kill -0 "$PROCESS_PID" 2>/dev/null; then
		cleanup_2
	fi
done

for PID in "${PIDS[@]}"; do
	if ! wait "$PID"; then
		echo "Process $PID failed. Exiting."
		cleanup_2
	fi
done

echo "All iterations completed successfully."

./calculate_throughput.sh

cleanup
