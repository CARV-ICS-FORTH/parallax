#!/usr/bin/env bash
set -euo pipefail
# This script takes the path to a file the recordcount and operationcount and generates the ycsb workloads. Finally it runs ycsb
# Invocation command ./run-ycsb.sh /path/to/file recordcount operationcount
if [ "$#" -ne 4 ]; then
	echo "./run-ycsb.sh /path/to/file recordcount operationcount workload"
	exit 1
fi

./mkfs.sh "$1" 1
./generate_workloads.py "$2" "$3"
./ycsb-edb -threads 1 -dbnum 1 -e execution_plan_a2d.txt -p "$1" -wl "$4"
mv RESULTS RESULTSATOD

./mkfs.sh "$1" 1
./ycsb-edb -threads 1 -dbnum 1 -e execution_plan_e.txt -p "$1" -wl "$4"
mv RESULTS RESULTSE
