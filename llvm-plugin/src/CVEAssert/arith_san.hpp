
#pragma once

#include "llvm/IR/Function.h"

void sanitizeDivideByZero(llvm::Function *F, std::optional<std::string> strategy);
void sanitizeDivideByZeroRecover(llvm::Function *F, std::optional<std::string> strategy);
llvm::Function *replaceUndesirableFunction(llvm::Function *F,
                                           llvm::CallInst *call);
void sanitizeDivideByZeroInFunction(llvm::Function *F,
                                    std::optional<std::string> funct_name);

void sanitizeIntOverflow(llvm::Function *F, std::optional<std::string> strategy);

void sanitizeIntOverflowRecover(llvm::Function *F, std::optional<std::string> strategy);

void sanitizeBinShift(llvm::Function *F);
