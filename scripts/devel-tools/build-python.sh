#!/bin/bash
# first build openssl since centos 7 have an outdated openssl for Python3.12
wget https://www.openssl.org/source/openssl-3.3.0.tar.gz && tar -xvf openssl-3.3.0.tar.gz && cd openssl-3.3.0 || exit
./config --prefix=/archive/users/gxanth/openssl3.3 --openssldir=/archive/users/gxanth/openssl3.3
make -j"$(nproc)"
make install
cd .. || exit

wget https://www.python.org/ftp/python/3.12.0/Python-3.12.0.tgz
tar -xvf Python-3.12.0.tgz
cd Python-3.12.0 || exit
CFLAGS="-I/archive/users/gxanth/openssl3.3/include/" LDFLAGS="${LDFLAGS} -Wl,-rpath=$LD_LIBRARY_PATH" ./configure --prefix=/archive/users/gxanth/python3.12 --with-openssl=/archive/users/gxanth/openssl3.3 --enable-optimizations --with-ensurepip=install
make -j"$(nproc)"
make install
