#!/bin/bash
GCCVERSION=10.1.0
mkdir temp
cd temp || exit
wget https://ftpmirror.gnu.org/gcc/gcc-"$GCCVERSION"/gcc-"$GCCVERSION".tar.gz
tar xf gcc-"$GCCVERSION".tar.gz
cd gcc-"$GCCVERSION" || exit
contrib/download_prerequisites
cd .. || exit
mkdir build
cd build || exit

../gcc-"$GCCVERSION"/configure -v --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --prefix=/archive/users/gxanth/gcc-"$GCCVERSION" --enable-checking=release --enable-languages=c,c++,fortran --disable-multilib --program-suffix=-"$GCCVERSION"

make -j 24
make install-strip
export PATH=/archive/users/gxanth/gcc-"$GCCVERSION"/bin:$PATH
export LD_LIBRARY_PATH=/archive/users/gxanth/gcc-"$GCCVERSION"/lib64:$LD_LIBRARY_PATH
