/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */


#pragma once

#include "llvm/IR/Function.h"

void sanitizeDivideByZero(llvm::Function *F);
void sanitizeDivideByZeroRecover(llvm::Function *F);
llvm::Function *replaceUndesirableFunction(llvm::Function *F,
                                           llvm::CallInst *call);
void sanitizeDivideByZeroinFunction(llvm::Function *F,
                                    std::optional<std::string> funct_name);
void sanitizeIntOverflow(llvm::Function *F);
void sanitizeIntOverflowRecover(llvm::Function *F);
void sanitizeBinShift(llvm::Function *F);
