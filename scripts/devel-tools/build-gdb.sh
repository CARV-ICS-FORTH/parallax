#!/bin/bash
GDBVERSION=10.1.0
mkdir temp
cd temp || exit
wget https://ftp.gnu.org/gnu/gdb/gdb-"$GDBVERSION".tar.xz
tar xf gdb-"$GDBVERSION".tar.gz
cd gdb-"$GDBVERSION" || exit
cd .. || exit
mkdir build
cd build || exit

../gdb-"$GDBVERSION"/configure --prefix=/archive/users/gxanth/gdb-"$GDBVERSION"
make -j 24
make install
