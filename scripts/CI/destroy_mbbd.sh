#!/usr/bin/env bash
set -euo pipefail

rm -rf "${NVME0:?}"/"${CI_JOB_ID:?}"
