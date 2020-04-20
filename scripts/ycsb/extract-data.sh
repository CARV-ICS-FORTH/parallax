#!/bin/bash

# 3 letter
# W-Workload - {L,R} Load, Run - {A,B,C,D,E,F} Workload type
# e.g. WLA - Workload Load A
declare -a arr=("Workload A Load")
WORKLOAD=(load_a)
CYCLES_PER_SECOND=76800000000

echo
for element in $(seq 0 $((${#WORKLOAD[@]} - 1))); do
	OPS=$(grep OVERALL ${WORKLOAD[$element]}/ops.txt | awk '{ print $3 }')
	OPS2=$(printf "%.1f", "$OPS")
	OPS="($(sed 's/[eE]+\{0,1\}/*10^/g' <<<"$OPS"))"

	USR_UTIL=$(grep all ${WORKLOAD[$element]}/mpstat-* | awk '{ print $4 }' | awk '{ sum += $1; n++ } END { if (n > 0) print (sum / n); }')
	SYS_UTIL=$(grep all ${WORKLOAD[$element]}/mpstat-* | awk '{ print $6 }' | awk '{ sum += $1; n++ } END { if (n > 0) print (sum / n); }')
	IOW_UTIL=$(grep all ${WORKLOAD[$element]}/mpstat-* | awk '{ print $7 }' | awk '{ sum += $1; n++ } END { if (n > 0) print (sum / n); }')
	IDL_UTIL=$(grep all ${WORKLOAD[$element]}/mpstat-* | awk '{ print $13 }' | awk '{ sum += $1; n++ } END { if (n > 0) print (sum / n); }')

	CPU_UTIL=$(grep all ${WORKLOAD[$element]}/mpstat-* | awk '{ print $13 }' | awk '{ sum += $1; n++ } END { if (n > 0) print 100 - (sum / n); }')
	echo ${arr[$element]}
	echo
	echo ${USR_UTIL} '% User CPU Util'
	echo ${SYS_UTIL} '% System CPU Util'
	echo ${IOW_UTIL} '% IO-Wait CPU Util'
	echo ${IDL_UTIL} '% Idle CPU Util'
	echo ${OPS2} 'ops/sec'
	echo ${CPU_UTIL} '% Average CPU Util'

	CPU_UTIL_DIV_100=$(echo "scale=2; $CPU_UTIL/100" | bc)
	TOTAL_CYCLES_NEEDED=$(echo "scale=2; $CPU_UTIL_DIV_100 * $CYCLES_PER_SECOND" | bc)
	CYCLES_PER_OP=$(echo "scale=2; $TOTAL_CYCLES_NEEDED / $OPS" | bc)

	echo $CYCLES_PER_OP 'cycles/op (with iowait)'

	CPU_UTIL=$(echo "scale=2; $CPU_UTIL - $IOW_UTIL" | bc)
	CPU_UTIL_DIV_100=$(echo "scale=2; $CPU_UTIL/100" | bc)
	TOTAL_CYCLES_NEEDED=$(echo "scale=2; $CPU_UTIL_DIV_100 * $CYCLES_PER_SECOND" | bc)
	CYCLES_PER_OP=$(echo "scale=2; $TOTAL_CYCLES_NEEDED / $OPS" | bc)

	echo $CYCLES_PER_OP 'cycles/op (without iowait)'

	./get_total_volume.sh ${WORKLOAD[$element]}/diskstats-before-* ${WORKLOAD[$element]}/diskstats-after-*
	echo
done
