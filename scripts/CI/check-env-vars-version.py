#!/usr/bin/env python3
import sys

with open("scripts/devel-tools/env-vars.sh", "r") as env_vars:
    env_vars_lines = env_vars.readlines()[-6:]

with open("scripts/devel-tools/build-gcc.sh", "r") as build_gcc:
    gcc_version = build_gcc.readlines()[2].split("=")[1].strip()

for line in env_vars_lines:
    if gcc_version not in line:
        print(f"Update line: {line.strip()} latest compiled gcc version: {gcc_version}")
        sys.exit(-1)

sys.exit(0)
