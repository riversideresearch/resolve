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


enum Cond { // Maybe adding an enum for all the possible conditions
    EQ = 1,
    GT = 2,
    GT_EQ = 3,
    LT = 4,
    LT_EQ = 5
};


// We will continue generalizing this following eval-2
Function *replaceUndesirableFunction(Function *F, unsigned int argNum) {
    Module *M = F->getParent();
    LLVMContext &Ctx = M->getContext();
    IRBuilder<> builder(Ctx);

    std::string handlerName = "resolve_sanitized_" + F->getName();

    if (Function *existingFn = M->getFunction(handlerName)) {
        return exisiting;
    }

    FunctionType *resolveSanitizedFnTy = F->getFunctionType();

    Function *resolveSanitizedFn = Function::Create(
        resolveSanitizedFnTy,
        Function::InternalLinkage,
        handlerName,
        M
    );

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolveSanitizedFn);
    // Insert a return instruction here.
    builder.SetInsertPoint(EntryBB);
    builder.CreateRet(F->getArg(0));
}

void sanitizeUndesirableOperationInFunction(Function *F, std::string fnName,
    unsigned int argNum) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  // Container to store call insts
  std::vector<CallInst> callsToReplace;
    
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
        if (calledFuncName == fnName) {
          callsToReplace.push_back(call);
        }
      }
    }
  }

  if (callsToReplace.size() == 0) {
    return;
  }
  
  // Construct the resolve_sanitize_func function
  Function *resolveSanitizedFn = replaceUndesirableFunction(F, argNum);

  // Replace calls at all callsites in the module
  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);

    // Get the arguments for the vulnerable function
    SmallVector<Value *, 2> fnArgs;
    for (unsigned int i = 0; i < call->arg_size(); ; ++i) {
        fnArgs.push_back(call->getOperand(i));
    } 

    auto sanitizedCall = builder.CreateCall(resolveSanitizedFn, fnArgs);

    // replace all callsites
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}