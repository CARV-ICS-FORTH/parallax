#!/bin/bash
export CC=gcc-9.1
export CXX=g++-9.1

mkdir llvm-project
cd llvm-project

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-9.0.1/llvm-9.0.1.src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-9.0.1/clang-9.0.1.src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-9.0.1/clang-tools-extra-9.0.1.src.tar.xz

tar -xf llvm-9.0.1.src.tar.xz
tar -xf clang-9.0.1.src.tar.xz
tar -xf clang-tools-extra-9.0.1.src.tar.xz

mv llvm-9.0.1.src llvm
mv clang-9.0.1.src clang
mv clang-tools-extra-9.0.1.src clang-tools-extra

mkdir build
cd build
cmake3 -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra"
ninja-build clang-format
echo "Export the bin directory to detect clang-format"
