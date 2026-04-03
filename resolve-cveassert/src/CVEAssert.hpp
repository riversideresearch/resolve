/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/GlobalVariable.h"

// Set value to true to get more verbose printouts
extern bool CVE_ASSERT_DEBUG;

extern llvm::DenseMap<llvm::Function *, llvm::GlobalVariable *> SanitizerMaps;
llvm::GlobalVariable *initSanitizerMap(llvm::Function &F);
