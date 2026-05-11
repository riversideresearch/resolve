/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Vulnerability.hpp"
#include "llvm/IR/Function.h"

llvm::Function *getOrCreateIsHeap(llvm::Function *F);
llvm::Function *getOrCreateFreeOfNonHeapSanitizer(
    llvm::Function *F, Vulnerability::RemediationStrategies strategy);
void sanitizeFreeOfNonHeap(llvm::Function *F,
                           Vulnerability::RemediationStrategies strategy);
