#!/bin/bash

trap 'echo "Interrupt signal received. Killing all processes..."; kill 0; exit 1' SIGINT

cleanup() {
	echo "A process failed. Killing all background processes..."
	kill 0
	exit 1
}
rm -rf RESULTS/*
for i in {1..32}; do
	echo "Starting iteration $i..."

	./ycsb-net -p /app/par.dat -insertStart 0 -clientProcesses 1 -stats on -o "./RESULTS/RESULTS$i" &
	PROCESS_PID=$!

	if ! kill -0 "$PROCESS_PID" 2>/dev/null; then
		cleanup
	fi
done

wait

echo "All iterations completed successfully."
