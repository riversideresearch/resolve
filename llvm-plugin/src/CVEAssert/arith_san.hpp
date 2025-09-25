
#pragma once

#include "llvm/IR/Function.h"

llvm::Function *replaceUndesirableFunction(llvm::Function *F, llvm::CallInst *call);
void sanitizeDivideByZero(llvm::Function *F);
void sanitizeDivideByZeroinFunction(llvm::Function *F, std::optional<std::string> funct_name);
