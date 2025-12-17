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

#include "undesirableop.hpp"

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


// Parameters
// 1. Which arguments to return (or zero)
// 2. Which arguments to test (if any)
// 3. Condition to test (equality, <, etc..) NOTE: not needed right now delay
// We will continue generalizing this following eval-2
// Change this function name to be "replaceUndesirableOperation" more generalized name
static Function *replaceUndesirableFunction(Function *F, CallInst *call, unsigned int argNum) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  std::string handlerName = "resolve_sanitized_" + call->getCalledFunction()->getName().str();

  if (Function *existingFn = M->getFunction(handlerName)) {
    return existingFn;
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
  builder.CreateRet(resolveSanitizedFn->getArg(0));

  // DEBUGGING
  raw_ostream &out = errs();
  out << *resolveSanitizedFn;
  if (verifyFunction(*resolveSanitizedFn, &out)) {}
  return resolveSanitizedFn;
}

void sanitizeUndesirableOperationInFunction(Function *F, std::string fnName,
    unsigned int argNum) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  // Container to store call insts
  std::vector<CallInst *> callsToReplace;
    
  // loop over each basic block in the vulnerable function
  for (auto &BB : *F) {
    // loop over each instruction
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();
        if (!calledFn) {
          continue;
        }

        StringRef calledFnName = calledFn->getName();
        if (calledFnName == fnName) {
          callsToReplace.push_back(call);
        }
      }
    }
  }

  if (callsToReplace.size() == 0) {
    return;
  }
  
  // Construct the resolve_sanitize_func function
  Function *resolveSanitizedFn = replaceUndesirableFunction(F, callsToReplace.front(), 0);

  // Replace calls at all callsites in the module
  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);

    // Get the arguments for the vulnerable function
    SmallVector<Value *, 2> fnArgs;
    for (unsigned int i = 0; i < call->arg_size(); ++i) {
        fnArgs.push_back(call->getOperand(i));
    } 

    auto sanitizedCall = builder.CreateCall(resolveSanitizedFn, fnArgs);

    // replace all callsites
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}