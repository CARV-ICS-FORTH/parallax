#!/bin/bash

set -x

if [ $# -ne 1 ]; then
	echo "Usage: stop_statistics.sh <result folder>"
	exit 1
fi

dir_results="$1"
TIME=$(date +"%T-%d-%m-%Y")
echo "$TIME" >>"${dir_results}/parsedate"

IOSTAT_PID=$(cat "${dir_results}/iostat_pid.txt")
MPSTAT_PID=$(cat "${dir_results}/mpstat_pid.txt")

if [ -n "$IOSTAT_PID" ]; then
	kill -9 "$IOSTAT_PID"
fi

if [ -n "$MPSTAT_PID" ]; then
	kill -9 "$MPSTAT_PID"
fi

cat /proc/diskstats >"${dir_results}/diskstats-after-$TIME" &
