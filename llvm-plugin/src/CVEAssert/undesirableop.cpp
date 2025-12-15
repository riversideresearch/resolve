/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "Vulnerability.hpp"

#include <vector>
#include <string>
#include <optional>

using namespace llvm;

Function *replaceUndesirableFunction(Function *F, unsigned int argNum, std::string cond, std::optional<std::string> fnName) {
    Module *M = F->getParent();
    LLVMContext &Ctx = M->getContext();
    IRBuilder<> builder(Ctx);

    std::string handlerName = "resolve_sanitized_fn_" + *fnName;

    if (Function *existingFn = M->getFunction(handlerName)) {
        return exisiting;
    }

    FunctionType *resolveSanitizedFnTy = F->getType();

    Function *resolveSanitizedFn = Function::Create(
        resolveSanitizedFnTy,
        Function::InternalLinkage,
        handlerName,
        M
    );

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolveSanitizedFn);
    BasicBlock *NormalBB = BasicBlock::Create(Ctx, "", resolveSanitizedFn);
    BasicBlock *SanitizedBB = BasicBlock::Create(Ctx, "", resolveSanitizedFn);
    
    builder.SetInsertPoint(EntryBB);

    // EntryBB: Contains condition instructions and branch 


    // NormalBB: Make call to vulnerable function
    
    // Sanitized 






}

void sanitizeUndesirableOperationInFunction(Function *F, std::optional<std::string> fnName,
    unsigned int argNum, std::string cond) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  // Container to store call insts
  std::vector<CallInst> callsToReplace;

  // Container to store arguments
  std::vector<Value *> fnArgs;
  
  // loop over each basic block in the vulnerable function
  for (auto &BB : *F) {
    // loop over each instruction
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();
        if (!calledFunc) {
          continue;
        }

        StringRef calledFnName = calledFunc->getName();
        if (calledFuncName == *funct_name) {
          callsToReplace.push_back(call);
        }
      }
    }
  }

  if (callsToReplace.size() == 0) {
    return;
  }

  // Get the arguments for the vulnerable function
  for (unsigned int i = 0; i <  ; ++i) {
    fnArgs.push_back(F->getArg(i)); /* TODO: Figure out how to get function arguments */
  }
  
  // Construct the resolve_sanitize_func function
  Function *resolveSanitizedFn = replaceUndesirableFunction(argNum, cond, *fnName);

  // Replace calls at all callsites in the module
  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);

    auto sanitizedCall = builder.CreateCall(resolveSanitizedFn, fnArgs);

    // replace all callsites
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}