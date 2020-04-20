#!/bin/bash

if [ $# -ne 1 ]; then
	echo 'Usage:  start_statistics.sh <result folder>'
	exit 1
fi

dir_results=$1
TIME=$(date +"%T-%d-%m-%Y")
echo $TIME >${dir_results}/parsedate
dir_collectl=${dir_results}/collectl-${TIME}
iostat -x 1 -t >${dir_results}/iostat-"$TIME" &
mpstat -P ALL 1 >${dir_results}/mpstat-"$TIME" &
#ifstat -t >  ${dir_results}/ifstat-$TIME &
#collectl -sCMN  -P -f${dir_collectl} &
cat /proc/diskstats >${dir_results}/diskstats-before-"$TIME" &
