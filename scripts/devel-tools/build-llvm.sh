#!/bin/bash
set -xeu
# shellcheck disable=SC2034
CC=gcc-12.1.0
# shellcheck disable=SC2034
CXX=g++-12.1.0
LLVMVERSION=14.0.6
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
# For release > 14 you need to modify the CMakelists.txt file and remove every reference to the LLVM_THIRD_PARTY variable
cmake3 -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;compiler-rt;lldb" -DCMAKE_BUILD_TYPE=Release

ninja-build clang clang-format clangd clang-tidy lldb llvm-symbolizer compiler-rt
echo "Export the bin directory to detect clang-format"
