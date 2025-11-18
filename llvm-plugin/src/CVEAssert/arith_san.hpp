/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once

#include "llvm/IR/Function.h"
#include "Vulnerability.hpp"
void sanitizeDivideByZero(llvm::Function *F, RemediationStrategies strategy);
void sanitizeDivideByZeroRecover(llvm::Function *F, RemediationStrategies strategy);
llvm::Function *replaceUndesirableFunction(llvm::Function *F,
                                           llvm::CallInst *call);
void sanitizeDivideByZeroInFunction(llvm::Function *F,
                                    std::optional<std::string> funct_name);
void sanitizeIntOverflow(llvm::Function *F, RemediationStrategies strategy);
void sanitizeIntOverflowRecover(llvm::Function *F, RemediationStrategies strategy);
void sanitizeBinShift(llvm::Function *F);
