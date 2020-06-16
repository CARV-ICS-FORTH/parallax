#!/bin/python3
import os
import sys

prefix = "./" + sys.argv[1]
files = [
    "/usr/local/include/kreon/kreon_rdma_client.h",
    "/usr/local/lib/libkreon_rdma.so",
    "/usr/local/lib/libkreonr.so",
    "/usr/local/lib/libkreon.so",
    "/usr/local/lib/libkreon_client.so",
    "/usr/local/bin/mkfs.kreon",
    "/usr/local/bin/kreon_server",
]

for f in files:
    filetocheck = prefix + f
    if not os.path.isfile(filetocheck):
        print("File {0} was not found".format(filetocheck))
        sys.exit(1)
