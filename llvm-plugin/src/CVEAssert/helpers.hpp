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

#include <string>

std::string getLLVMType(llvm::Type *ty);
llvm::Function *getOrCreateIsHeap(llvm::Module *M, llvm::LLVMContext &Ctx);
llvm::Function *getOrCreateResolveReportSanitizerTriggered(llvm::Module *M);
llvm::Function *getOrCreateRemediationBehavior(llvm::Module *M, Vulnerability::RemediationStrategies strategy);
llvm::Function *getOrCreateWeakResolveMalloc(llvm::Module *M);
llvm::Function *getOrCreateWeakResolveStackObj(llvm::Module *M);
llvm::Function *getOrCreateWeakResolveFree(llvm::Module *M);