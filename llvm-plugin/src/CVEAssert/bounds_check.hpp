/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once

#include "llvm/IR/Function.h"

void sanitizeLoadStore(llvm::Function *f, llvm::ModuleAnalysisManager &MAM);
void sanitizeMemcpy(llvm::Function *f, llvm::ModuleAnalysisManager &MAM);
void sanitizeMemInstBounds(llvm::Function *f, llvm::ModuleAnalysisManager &MAM, RemediationStrategies strategy);