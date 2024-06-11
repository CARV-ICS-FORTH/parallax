#!/bin/bash
set -xeu
export CC=gcc-14.1.0
export CXX=g++-14.1.0
LLVMVERSION=18.1.0
mkdir llvm-project
cd llvm-project || exit

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/llvm-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/clang-tools-extra-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/compiler-rt-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/lldb-"$LLVMVERSION".src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-"$LLVMVERSION"/cmake-"$LLVMVERSION".src.tar.xz

tar -xvf llvm-"$LLVMVERSION".src.tar.xz
tar -xvf clang-"$LLVMVERSION".src.tar.xz
tar -xvf clang-tools-extra-"$LLVMVERSION".src.tar.xz
tar -xvf compiler-rt-"$LLVMVERSION".src.tar.xz
tar -xvf lldb-"$LLVMVERSION".src.tar.xz
tar -xvf cmake-"$LLVMVERSION".src.tar.xz

mv llvm-"$LLVMVERSION".src llvm
mv clang-"$LLVMVERSION".src clang
mv clang-tools-extra-"$LLVMVERSION".src clang-tools-extra
mv compiler-rt-"$LLVMVERSION".src compiler-rt
mv lldb-"$LLVMVERSION".src lldb
mv cmake-"$LLVMVERSION".src cmake

mkdir build
cd build || exit
/archive/users/gxanth/cmake-3.29/bin/cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt;lldb" -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF
ninja-build clang clang-format clangd clang-tidy lldb llvm-symbolizer compiler-rt
