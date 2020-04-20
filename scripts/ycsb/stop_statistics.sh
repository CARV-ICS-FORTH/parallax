#!/bin/bash

set -x

if [ $# -ne 1 ]; then
	echo 'Usage:  stop_statistics.sh <result folder>'
	exit 1
fi

dir_results=$1
TIME=$(date +"%T-%d-%m-%Y")
echo $TIME >>${dir_results}/parsedate
killall -9 iostat mpstat
#ps aux | grep collectl | awk '{print $2}' | xargs kill -15
cat /proc/diskstats >${dir_results}/diskstats-after-"$TIME" &
