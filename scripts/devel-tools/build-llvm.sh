#!/bin/bash
set -xeu
export CC=gcc-11.1.0
export CXX=g++-11.1.0
LLVMVERSION=12.0.1
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
ninja-build clang
ninja-build clang-format
ninja-build clangd
echo "Export the bin directory to detect clang-format"
