/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "resolve_facts_llvm/BinaryLLVMFacts.hpp"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace resolve {
std::string binaryTypeToString(const Type &type);

void getBinaryGlobalFacts(BinaryLLVMFacts &facts, GlobalVariable &G);

void getBinaryFunctionFacts(BinaryLLVMFacts &facts, Function &F);

void getBinaryModuleFacts(BinaryLLVMFacts &facts, Module &M);

// Embed the accumulated facts into custom ELF sections.
void embedBinaryFacts(Module &M, ArrayRef<uint8_t> facts);
} // namespace resolve
