#!/bin/python3
import os
import sys

prefix = "./" + sys.argv[1]
files = [
    "/usr/local/lib/libkreon.so",
    "/usr/local/lib/libkreon.a",
    "/usr/local/bin/mkfs.kreon",
]

for f in files:
    filetocheck = prefix + f
    if not os.path.isfile(filetocheck):
        print("File {0} was not found".format(filetocheck))
        sys.exit(1)
