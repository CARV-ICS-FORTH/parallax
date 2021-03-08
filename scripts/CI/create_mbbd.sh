#!/usr/bin/env bash
set -euo pipefail

fallocate -l 8G /tmp/kv_store.dat
