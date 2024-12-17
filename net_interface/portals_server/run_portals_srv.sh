#!/bin/bash

OUTPUT_DIR="./cpu_results"
CPU_UTIL_FILE="${OUTPUT_DIR}/cpu_utilization.txt"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

cleanup() {
	echo "Stopping server..."
	pkill -f "portals_parallax_server"
	echo "Stopping CPU utilization monitoring..."
	kill "$MPSTAT_PID" 2>/dev/null
	wait "$MPSTAT_PID" 2>/dev/null
	echo "CPU utilization during execution (Average):"
	grep 'Average:' "$CPU_UTIL_FILE"
	exit
}

trap cleanup SIGINT

mpstat 1 >"$CPU_UTIL_FILE" &
MPSTAT_PID=$!

echo "Starting server..."
./portals_parallax_server -t 32 -f /app/par.dat -L0 4 -GF 4 -pf &
SERVER_PID=$!

echo "Server running... Press Ctrl+C to stop."
wait "$SERVER_PID"

cleanup
