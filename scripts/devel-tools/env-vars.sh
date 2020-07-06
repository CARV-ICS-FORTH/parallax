#!/bin/bash
# shellcheck disable=SC2034

PATH=/archive/users/gxanth/llvm-project/build/bin:$PATH
PATH=/archive/users/gxanth/git/bin:$PATH
PATH=$PATH:/archive/users/gxanth/go/bin
PATH=/archive/users/gxanth/shellcheck-stable:$PATH
PATH=$PATH:/archive/users/gxanth/go/bin
PATH=$PATH:$HOME/go/bin
PATH=/archive/users/gxanth/gcc-10.1.0/bin:$PATH
LD_LIBRARY_PATH=/archive/users/gxanth/gcc-10.1.0/lib64:$LD_LIBRARY_PATH
PATH=/archive/users/gxanth/gdb9.2/bin:$PATH
CC=gcc-10.1.0
CXX=g++-10.1.0
