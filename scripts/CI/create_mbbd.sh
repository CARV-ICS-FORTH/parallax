#!/usr/bin/env bash
set -euo pipefail

mkdir -p /ycsb_data
mount -t tmpfs tmpfs /ycsb_data
fallocate -l 50G /ycsb_data/kv_store.dat
