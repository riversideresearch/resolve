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
#include "Vulnerability.hpp"

#include <optional>
#include <string>
#include <vector>

using namespace llvm;

// Parameters
// 1. Which arguments to return (or zero)
// 2. Which arguments to test (if any)
// 3. Condition to test (equality, <, etc..) NOTE: not needed right now delay
// We will continue generalizing this following eval-2
// Change this function name to be "replaceUndesirableOperation" more
// generalized name
static Function *getOrCreateContractWrapper(Module *M, CallInst *call,
                                            unsigned int argNum) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  Function *originalFn = call->getCalledFunction();

  std::string handlerName = "__cve_contract_" + originalFn->getName().str();

  FunctionType *wrapperTy = originalFn->getFunctionType();

  Function *resolveWrapperFn =
      getOrCreateResolveHelper(M, handlerName, wrapperTy);

  SmallVector<Value *> Args;
  for (Argument &arg : resolveWrapperFn->args()) {
    Args.push_back(&arg);
  }

  if (!resolveWrapperFn->empty()) {
    recordPatchFunction(resolveWrapperFn);
    return resolveWrapperFn;
  }

  // TODO: Create 3 basic blocks
  // 1. Preconditions
  // 2. Valid path
  // 3. Recovery path
  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveWrapperFn);
  // Insert a return instruction here.
  builder.SetInsertPoint(EntryBB);

  // TODO: Create helper to generate the llvm-ir for preconditions
  // TODO: Create helper to generate valid path (call original operation
  // contract)
  // TODO: Create helper to generate recovery path
  builder.CreateCall(originalFn, Args);
  builder.CreateRet(resolveWrapperFn->getArg(argNum));

  validateIR(resolveWrapperFn);
  recordPatchFunction(resolveWrapperFn);
  return resolveWrapperFn;
}

void sanitizeContract(Function *F, std::string fnName, unsigned int argNum) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<CallInst *> callsToReplace;

  for (auto &BB : *F) {
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

  Function *resolveWrapperFn =
      getOrCreateContractWrapper(M, callsToReplace.front(), argNum);

  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);
    SmallVector<Value *, 2> fnArgs;
    for (unsigned int i = 0; i < call->arg_size(); ++i) {
      fnArgs.push_back(call->getOperand(i));
    }

    auto resolveWrapperCall = builder.CreateCall(resolveWrapperFn, fnArgs);
    call->replaceAllUsesWith(resolveWrapperCall);
    call->eraseFromParent();
  }
}
