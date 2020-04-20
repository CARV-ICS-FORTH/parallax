#!/bin/bash

wget https://ftpmirror.gnu.org/gcc/gcc-9.1.0/gcc-9.1.0.tar.gz
tar xf gcc-9.1.0.tar.gz
cd gcc-9.1.0 || exit
contrib/download_prerequisites
cd ..
mkdir build
cd build || exit

../gcc-9.1.0/configure -v --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --prefix=/archive/users/gxanth/gcc-9.1 --enable-checking=release --enable-languages=c,c++,fortran --disable-multilib --program-suffix=-9.1

make -j 24

export PATH=/archive/users/gxanth/gcc-9.1/bin:$PATH
export LD_LIBRARY_PATH=/archive/users/gxanth/gcc-9.1/lib64:$LD_LIBRARY_PATH
