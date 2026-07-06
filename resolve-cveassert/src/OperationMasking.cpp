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

#include "IRUtils.hpp"

#include <optional>
#include <string>
#include <vector>

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
// Change this function name to be "replaceUndesirableOperation" more
// generalized name
static Function *getOrCreateMaskOperation(Module *M, CallInst *call,
                                          unsigned int argNum) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  std::string handlerName =
      "__cve_mask_" + call->getCalledFunction()->getName().str();

  FunctionType *maskFnTy = call->getCalledFunction()->getFunctionType();

  Function *maskedFn = getOrCreateResolveHelper(M, handlerName, maskFnTy);

  if (!maskedFn->empty()) {
    recordPatchFunction(maskedFn);
    return maskedFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", maskedFn);
  // Insert a return instruction here.
  builder.SetInsertPoint(EntryBB);
  builder.CreateRet(maskedFn->getArg(argNum));

  validateIR(maskedFn);
  recordPatchFunction(maskedFn);
  return maskedFn;
}

void maskOperationInFunction(Function *F, std::string fnName,
                             unsigned int argNum) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<CallInst *> callsToMask;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();
        if (!calledFn) {
          continue;
        }

        StringRef calledFnName = calledFn->getName();
        if (calledFnName == fnName) {
          callsToMask.push_back(call);
        }
      }
    }
  }

  if (callsToMask.size() == 0) {
    return;
  }

  // Mask the unsafe operation
  Function *maskedFn = getOrCreateMaskOperation(M, callsToMask.front(), argNum);

  // Replace calls at all callsites in the module
  for (auto call : callsToMask) {
    builder.SetInsertPoint(call);

    // Get the arguments for the vulnerable function
    SmallVector<Value *, 2> fnArgs;
    for (unsigned int i = 0; i < call->arg_size(); ++i) {
      fnArgs.push_back(call->getOperand(i));
    }

    auto maskedCall = builder.CreateCall(maskedFn, fnArgs);
    call->replaceAllUsesWith(maskedCall);
    call->eraseFromParent();
  }
}
