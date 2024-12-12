#!/bin/bash

SERVER="./portals_parallax_server"
SERVER_ARGS="-t 32 -f /app/par.dat -L0 4 -GF 4 -pf"
FLAMEGRAPH_DIR="./FlameGraph"
OUTPUT_DIR="./profile_results"
FLAMEGRAPH_FILE="${OUTPUT_DIR}/flamegraph.svg"

if [ ! -x "$SERVER" ]; then
	echo "Error: Server executable $SERVER not found or not executable."
	exit 1
fi

if [ ! -d "$FLAMEGRAPH_DIR" ]; then
	echo "Flamegraph repository not found. Cloning..."
	if ! git clone "$FLAMEGRAPH_REPO" "$FLAMEGRAPH_DIR"; then
		echo "Error: Failed to clone the Flamegraph repository."
		exit 1
	fi
fi

mkdir -p "$OUTPUT_DIR"

cleanup() {
	echo "Stopping perf and the server..."
	kill -SIGINT "$SERVER_PID" 2>/dev/null
	wait "$SERVER_PID" 2>/dev/null
	perf script >"${OUTPUT_DIR}/out.perf"
	echo "Collapsing stacks for Flamegraph..."
	"${FLAMEGRAPH_DIR}/stackcollapse-perf.pl" "${OUTPUT_DIR}/out.perf" >"${OUTPUT_DIR}/out.folded"
	echo "Generating flamegraph..."
	"${FLAMEGRAPH_DIR}/flamegraph.pl" "${OUTPUT_DIR}/out.folded" >"$FLAMEGRAPH_FILE"
	echo "Flamegraph generated: $FLAMEGRAPH_FILE"
	exit
}

trap cleanup SIGINT

echo "Starting perf profiling..."
perf record -F 99 -g -- $SERVER "$SERVER_ARGS" &
SERVER_PID=$!

# wait Ctrl+C interrupt to the server
echo "Profiling... Press Ctrl+C to stop."
wait $SERVER_PID
