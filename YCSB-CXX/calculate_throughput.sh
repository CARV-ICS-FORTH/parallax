#!/bin/bash

cd RESULTS || {
	echo "RESULTS directory not found!"
	exit 1
}

total_throughput=0

for result_dir in RESULT*; do
	if [ -f "$result_dir/run_a/ops.txt" ]; then
		throughput=$(grep "\[OVERALL\] Throughput" "$result_dir/run_a/ops.txt" | awk '{print $3}')
		if [[ $throughput =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
			total_throughput=$(awk "BEGIN {print $total_throughput + $throughput}")
		else
			echo "Warning: Invalid throughput value in $result_dir/run_a/ops.txt. Skipping."
		fi
	else
		echo "Warning: Missing ops.txt in $result_dir. Skipping."
	fi
done

printf "Final Total Throughput: %.2f ops/sec\n" "$total_throughput"
