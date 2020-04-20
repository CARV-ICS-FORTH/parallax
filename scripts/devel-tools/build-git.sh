#!/bin/bash

wget https://github.com/git/git/archive/v2.26.0.tar.gz
tar -xf v2.26.0.tar.gz
cd git-2.26.0 || exit
make configure
./configure --prefix=/archive/users/gxanth/git
make -j 12
make install
