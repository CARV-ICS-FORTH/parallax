#!/usr/bin/env python3
import sys
import os
from os import listdir
from os.path import isfile, join

# This utility generates ycsb workload files with the provided operation and record counts.
# Invocation command ./generate_workloads 1000 1000
workloads_path = "workloads/"
onlyfiles = [f for f in listdir(workloads_path) if isfile(join(workloads_path, f))]
temp_buffers = {}

if len(sys.argv) != 3:
    print("./generate_workloads recordcount operationcount")
    sys.exit(os.EX_NOINPUT)

for filename in onlyfiles:
    rel_path = workloads_path + filename
    with open(rel_path, "r") as file:
        temp_buffers[rel_path] = file.readlines()

for k, _ in temp_buffers.items():
    os.remove(k)

for filename in onlyfiles:
    rel_path = workloads_path + filename
    with open(rel_path, "w") as file:
        print(rel_path)
        for line in temp_buffers[rel_path]:
            if "recordcount" in line:
                file.write(f"recordcount={sys.argv[1]}\n")
            elif "operationcount" in line:
                file.write(f"operationcount={sys.argv[2]}\n")
            else:
                file.write(line)
