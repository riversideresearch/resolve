/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once
#include "Vulnerability.hpp"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <string>

#define RESOLVE_PREFIX "__resolve_"
#define CVE_PREFIX "__cve_"
#define RESOLVE_FN(name) RESOLVE_PREFIX name
#define CVE_FN(name) CVE_PREFIX name

std::string getLLVMType(llvm::Type *ty);
llvm::Function *getOrCreateResolveReportSanitizerTriggered(llvm::Module *M);
llvm::Function *
getOrCreateRemediationBehavior(llvm::Module *M,
                               Vulnerability::RemediationStrategies strategy);
llvm::Function *
getOrCreateResolveHelper(llvm::Module *M, std::string fn_name,
                         llvm::FunctionType *fn_type,
                         llvm::GlobalValue::LinkageTypes link_type =
                             llvm::Function::InternalLinkage);
void validateIR(llvm::Function *F);

void beginPatchRecording(void);
void recordPatchFunction(llvm::Function *F);
void recordPatchGlobal(llvm::GlobalVariable *G);
void endPatchRecordingAndWrite(llvm::Function *F);

llvm::Function *getOrCreateSanitizerMapEntry(llvm::Module *M);
void createSanitizerGateBranch(llvm::IRBuilder<> &Builder, llvm::Function *F,
                               uint64_t Index, llvm::BasicBlock *DisabledBB,
                               llvm::BasicBlock *EnabledBB);
