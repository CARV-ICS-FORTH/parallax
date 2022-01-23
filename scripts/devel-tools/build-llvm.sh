#!/bin/bash
set -xeu
export CC=gcc-11.1.0
export CXX=g++-11.1.0
LLVMVERSION=13.0.0
mkdir llvm-project
cd llvm-project || exit

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/llvm-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-tools-extra-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/compiler-rt-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/lldb-"$LLVMVERSION".src.tar.xz

tar -xvf llvm-"$LLVMVERSION".src.tar.xz
tar -xvf clang-"$LLVMVERSION".src.tar.xz
tar -xvf clang-tools-extra-"$LLVMVERSION".src.tar.xz
tar -xvf compiler-rt-"$LLVMVERSION".src.tar.xz
tar -xvf lldb-"$LLVMVERSION".src.tar.xz

mv llvm-"$LLVMVERSION".src llvm
mv clang-"$LLVMVERSION".src clang
mv clang-tools-extra-"$LLVMVERSION".src clang-tools-extra
mv compiler-rt-"$LLVMVERSION".src compiler-rt
mv lldb-"$LLVMVERSION".src lldb

mkdir build
cd build || exit
cmake3 -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt;lldb" -DCMAKE_BUILD_TYPE=Release

ninja-build clang
ninja-build clang-format
ninja-build clangd
ninja-build clang-tidy
ninja-build lldb
ninja-build compiler-rt
echo "Export the bin directory to detect clang-format"
