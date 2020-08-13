#!/bin/python3
# Given a directory containing at least 2 static libraries (.a),
# it unpacks their .o files in different directories and repacks them in a single static library called libkreon2.a.
# Hopefully this script will be removed if this can be done through cmake.
# ./pack-staticlib.py path/to/dir/with/static/libraries

import glob, os, sys
from pathlib import Path

os.chdir(sys.argv[1])

# Detects the names of all the static libraries in the directory
def findfilestopack():
    filestopack = []

    for file in glob.glob("*.a"):
        filestopack.append(file)

    return filestopack


# Unpacks every library in its own directory and then repacks it in a single file
def unpackeachstaticlib(filestopack):
    basedir = os.getcwd()

    # Unpack every .o file from the static libraries in separate directories
    # We need to unpack in different directories in case overlapping symbols occur.
    concatdirs = ""
    for file in filestopack:
        unpackdir = Path(file).resolve().stem
        os.mkdir(unpackdir)
        concatdirs = concatdirs + " " + unpackdir + "/*"
        os.chdir(unpackdir)
        os.system("ar -x ../" + file)
        os.chdir(basedir)

    basecommand = "ar -qc libkreon2.a "
    os.system(basecommand + concatdirs)


filestopack = findfilestopack()
assert len(filestopack) != 0
unpackeachstaticlib(filestopack)
