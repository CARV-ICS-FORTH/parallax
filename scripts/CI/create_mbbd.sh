#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$NVME0"/"$CI_JOB_ID"/
fallocate -l 14G "$NVME0"/"$CI_JOB_ID"/kv_store.dat
