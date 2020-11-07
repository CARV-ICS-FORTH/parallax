#!/bin/python3

import sys, os

workloads_folder = "ycsb_execution_plans"

if len(sys.argv) != 3:
    print(
        "\033[1;31m"
        + "E: Usage: ./set_operations.py <num of operations> <num of clients>"
        + "\033[1;39m"
    )
    sys.exit(-1)

ops = int(sys.argv[1])
clients = int(sys.argv[2])

for wfilename in ["workloada", "workloadb", "workloadc", "workloadd", "workloadf"]:
    wfile = open(workloads_folder + "/" + wfilename, "r")
    newwfile = open("tmp_" + wfilename, "w")
    for line in wfile:
        if "recordcount" in line:
            newwfile.write("recordcount=" + str(clients * ops) + "\n")
        elif "operationcount" in line:
            newwfile.write("operationcount=" + str(ops) + "\n")
        else:
            newwfile.write(line)
    wfile.close()
    newwfile.close()
    os.system("mv " + "tmp_" + wfilename + " " + workloads_folder + "/" + wfilename)
