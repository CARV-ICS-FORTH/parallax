#!/bin/python3
import os
import sys

prefix = "./" + sys.argv[1]
files = [
    "/usr/local/lib/libparallax.so",
    "/usr/local/lib/libparallax.a",
    "/usr/local/bin/kv_format.parallax",
]

for f in files:
    filetocheck = prefix + f
    if not os.path.isfile(filetocheck):
        print("File {0} was not found".format(filetocheck))
        sys.exit(1)
