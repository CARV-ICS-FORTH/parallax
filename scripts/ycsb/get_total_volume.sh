#!/bin/bash

if [ $# -ne 2 ]; then
	echo 'Usage: get_total_volume.sh <diskstats before> <diskstats after>'
	exit 1
fi

DSTATS_BEFORE=$1
DSTATS_AFTER=$2

R_SEC_BEFORE_SDB=$(grep sdb ${DSTATS_BEFORE} | awk '{ print $6 }')
R_SEC_BEFORE_SDC=$(grep sdc ${DSTATS_BEFORE} | awk '{ print $6 }')
R_SEC_BEFORE_SDD=$(grep sdd ${DSTATS_BEFORE} | awk '{ print $6 }')
R_SEC_BEFORE_SDE=$(grep sde ${DSTATS_BEFORE} | awk '{ print $6 }')
R_SEC_BEFORE_SDF=$(grep sdf ${DSTATS_BEFORE} | awk '{ print $6 }')
R_SEC_BEFORE_NVM=$(grep nvme0n1 ${DSTATS_BEFORE} | awk '{ print $6 }')

W_SEC_BEFORE_SDB=$(grep sdc ${DSTATS_BEFORE} | awk '{ print $10 }')
W_SEC_BEFORE_SDC=$(grep sdc ${DSTATS_BEFORE} | awk '{ print $10 }')
W_SEC_BEFORE_SDD=$(grep sdd ${DSTATS_BEFORE} | awk '{ print $10 }')
W_SEC_BEFORE_SDE=$(grep sde ${DSTATS_BEFORE} | awk '{ print $10 }')
W_SEC_BEFORE_SDF=$(grep sdf ${DSTATS_BEFORE} | awk '{ print $10 }')
W_SEC_BEFORE_NVM=$(grep nvme0n1 ${DSTATS_BEFORE} | awk '{ print $10 }')

R_SEC_AFTER_SDB=$(grep sdb ${DSTATS_AFTER} | awk '{ print $6 }')
R_SEC_AFTER_SDC=$(grep sdc ${DSTATS_AFTER} | awk '{ print $6 }')
R_SEC_AFTER_SDD=$(grep sdd ${DSTATS_AFTER} | awk '{ print $6 }')
R_SEC_AFTER_SDE=$(grep sde ${DSTATS_AFTER} | awk '{ print $6 }')
R_SEC_AFTER_SDF=$(grep sdf ${DSTATS_AFTER} | awk '{ print $6 }')
R_SEC_AFTER_NVM=$(grep nvme0n1 ${DSTATS_AFTER} | awk '{ print $6 }')

W_SEC_AFTER_SDB=$(grep sdb ${DSTATS_AFTER} | awk '{ print $10 }')
W_SEC_AFTER_SDC=$(grep sdc ${DSTATS_AFTER} | awk '{ print $10 }')
W_SEC_AFTER_SDD=$(grep sdd ${DSTATS_AFTER} | awk '{ print $10 }')
W_SEC_AFTER_SDE=$(grep sde ${DSTATS_AFTER} | awk '{ print $10 }')
W_SEC_AFTER_SDF=$(grep sdf ${DSTATS_AFTER} | awk '{ print $10 }')
W_SEC_AFTER_NVM=$(grep nvme0n1 ${DSTATS_AFTER} | awk '{ print $10 }')

TOTAL_RD_SEC_BEFORE=$(expr ${R_SEC_BEFORE_SDC} + ${R_SEC_BEFORE_SDD} + ${R_SEC_BEFORE_SDE} + ${R_SEC_BEFORE_SDF} + ${R_SEC_BEFORE_SDB} + ${R_SEC_BEFORE_NVM})
TOTAL_WR_SEC_BEFORE=$(expr ${W_SEC_BEFORE_SDC} + ${W_SEC_BEFORE_SDD} + ${W_SEC_BEFORE_SDE} + ${W_SEC_BEFORE_SDF} + ${W_SEC_BEFORE_SDB} + ${W_SEC_BEFORE_NVM})

TOTAL_RD_SEC_AFTER=$(expr ${R_SEC_AFTER_SDC} + ${R_SEC_AFTER_SDD} + ${R_SEC_AFTER_SDE} + ${R_SEC_AFTER_SDF} + ${R_SEC_AFTER_SDB} + ${R_SEC_AFTER_NVM})
TOTAL_WR_SEC_AFTER=$(expr ${W_SEC_AFTER_SDC} + ${W_SEC_AFTER_SDD} + ${W_SEC_AFTER_SDE} + ${W_SEC_AFTER_SDF} + ${W_SEC_AFTER_SDB} + ${W_SEC_AFTER_NVM})

DIFF_SEC_READ=$(expr ${TOTAL_RD_SEC_AFTER} - ${TOTAL_RD_SEC_BEFORE})
DIFF_SEC_WRITE=$(expr ${TOTAL_WR_SEC_AFTER} - ${TOTAL_WR_SEC_BEFORE})

DIFF_BYTES_READ=$(expr ${DIFF_SEC_READ} \* 512)
DIFF_BYTES_WRITE=$(expr ${DIFF_SEC_WRITE} \* 512)

DIFF_GB_READ=$(expr ${DIFF_BYTES_READ} / 1024 / 1024)
DIFF_GB_WRITE=$(expr ${DIFF_BYTES_WRITE} / 1024 / 1024)

echo 'Total writes' ${DIFF_GB_WRITE} 'MBs'
echo 'Total reads' ${DIFF_GB_READ} 'MBs'
