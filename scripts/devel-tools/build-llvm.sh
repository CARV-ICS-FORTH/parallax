#!/bin/bash
export CC=gcc-9.1
export CXX=g++-9.1
LLVMVERSION=10.0.0
mkdir llvm-project
cd llvm-project || exit

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/llvm-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-tools-extra-"$LLVMVERSION".src.tar.xz

tar -xf llvm-"$LLVMVERSION".src.tar.xz
tar -xf clang-"$LLVMVERSION".src.tar.xz
tar -xf clang-tools-extra-"$LLVMVERSION".src.tar.xz

mv llvm-"$LLVMVERSION".src llvm
mv clang-"$LLVMVERSION".src clang
mv clang-tools-extra-"$LLVMVERSION".src clang-tools-extra

mkdir build
cd build || exit
cmake3 -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra"
ninja-build clang-format
echo "Export the bin directory to detect clang-format"
