/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/ADT/StringRef.h"
#include "Vulnerability.hpp"
/* Helper function to get the argument type as a string */
inline llvm::StringRef getLLVMType(llvm::Type *ty) {
    if (ty->isPointerTy())          return "ptr";
    if (ty->isIntegerTy(8))         return "i8";
    if (ty->isIntegerTy(16))        return "i16";
    if (ty->isIntegerTy(32))        return "i32";
    if (ty->isIntegerTy(64))        return "i64";
    if (ty->isFloatingPointTy())    return "float";
    return "";
}
llvm::Function *getOrCreateIsHeap(llvm::Module *M, llvm::LLVMContext &Ctx);
llvm::Function *getOrCreateResolveReportSanitizerTriggered(llvm::Module *M);
llvm::Function *getOrCreateRemediationBehavior(llvm::Module *M, RemediationStrategies strategy);