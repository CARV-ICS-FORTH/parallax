#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: start_statistics.sh <result folder>"
	exit 1
fi

dir_results="$1"
TIME=$(date +"%T-%d-%m-%Y")
echo "$TIME" >"${dir_results}/parsedate"

iostat -x 1 -t >"${dir_results}/iostat-$TIME" &
IOSTAT_PID=$!
mpstat -P ALL 1 >"${dir_results}/mpstat-$TIME" &
MPSTAT_PID=$!

echo "$IOSTAT_PID" >"${dir_results}/iostat_pid.txt"
echo "$MPSTAT_PID" >"${dir_results}/mpstat_pid.txt"

cat /proc/diskstats >"${dir_results}/diskstats-before-$TIME" &
