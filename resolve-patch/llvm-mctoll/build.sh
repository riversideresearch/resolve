#!/usr/bin/env bash 
#
# Copyright (c) 2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

set -e

git clone https://github.com/llvm/llvm-project.git _llvm-project

cd _llvm-project && git clone -b master https://github.com/microsoft/llvm-mctoll.git llvm/tools/llvm-mctoll

git checkout 8dfdcc7b7bf66834a761bd8de445840ef68e4d1a

cmake -S llvm -B . -G "Ninja" \
  -DLLVM_TARGETS_TO_BUILD="X86;ARM"  \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_ENABLE_ASSERTIONS=true      \
  -DCLANG_DEFAULT_PIE_ON_LINUX=OFF   \
  -DCMAKE_BUILD_TYPE=Release

cmake --build  . -- llvm-mctoll