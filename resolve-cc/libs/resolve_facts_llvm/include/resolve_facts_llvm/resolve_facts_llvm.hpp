/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "resolve_facts.hpp"
#include "LLVMFacts.hpp"

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
#include "llvm/Support/Compression.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace resolve {
  static ProgramFacts all_facts;
  static LLVMFacts facts(all_facts);

  std::string debugLocToString(DebugLoc dbgLoc);

  std::string typeToString(const Type &type);

  void getGlobalFacts(GlobalVariable &G);

  void getFunctionFacts(Function &F);

  void getModuleFacts(Module &M);

  // Embed the accumulated facts into custom ELF sections.
  void embedFacts(Module &M);
}
