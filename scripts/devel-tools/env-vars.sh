#!/bin/bash
# shellcheck disable=SC2034

PATH=/archive/users/gxanth/llvm-project/build/bin:$PATH
PATH=/archive/users/gxanth/git/bin:$PATH
PATH=$PATH:/archive/users/gxanth/go/bin
PATH=/archive/users/gxanth/shellcheck-stable:$PATH
PATH=$PATH:$HOME/go/bin
PATH=/archive/users/gxanth/gdb13.2/bin:$PATH
PATH=/archive/users/gxanth/gcc-14.1.0/bin:$PATH
LD_LIBRARY_PATH=/archive/users/gxanth/gcc-14.1.0/lib64:$LD_LIBRARY_PATH
CC=gcc-14.1.0
CXX=g++-14.1.0
AR=gcc-ar-14.1.0
CPP=cpp-14.1.0
