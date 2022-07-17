#!/usr/bin/env bash
set -xeu

VERSION="2.38"
wget https://ftp.gnu.org/gnu/binutils/binutils-"$VERSION".tar.xz
tar -xf binutils-"$VERSION".tar.xz

cd binutils-"$VERSION"
mkdir build && cd build
../configure --prefix=/archive/users/gxanth/binutils"$VERSION"
make -j "$(nproc)"
make install
