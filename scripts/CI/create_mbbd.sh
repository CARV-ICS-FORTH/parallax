#!/usr/bin/env bash
set -euo pipefail

fallocate -l 14G /tmp/kv_store.dat
