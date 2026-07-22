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

#include "Contract.hpp"
#include "IRUtils.hpp"
#include "Remediation.hpp"

#include <optional>
#include <string>
#include <vector>

using namespace llvm;

static void emitPreconditions(Function *wrapperFn, BasicBlock *entryBB,
                              BasicBlock *validBB, BasicBlock *recoverBB,
                              Contract contract) {
  LLVMContext &Ctx = wrapperFn->getContext();
  IRBuilder<> builder(Ctx);
  // Extract preconditions from contract (hard coding for testing)
  Precondition precond = contract.preconditions[0];

  builder.SetInsertPoint(entryBB);

  // Check the predicate
  Value *Cond = nullptr;
  // Fetch wrapper argument
  Argument *arg = wrapperFn->getArg(precond.arg0);
  if (precond.kind == PredicateKind::NonZero) {
    Value *zero = ConstantInt::get(arg->getType(), 0);
    Cond = builder.CreateICmpEQ(arg, zero);
  }

  builder.CreateCondBr(Cond, recoverBB, validBB);
}

static void emitValidPath(BasicBlock *block, Function *wrapperFn,
                          Function *origFn) {
  LLVMContext &Ctx = wrapperFn->getContext();
  IRBuilder<> builder(Ctx);

  SmallVector<Value *> Args;
  for (Argument &arg : wrapperFn->args()) {
    Args.push_back(&arg);
  }

  builder.SetInsertPoint(block);

  Value *opVal = builder.CreateCall(origFn, Args);

  if (wrapperFn->getReturnType()->isVoidTy()) {
    builder.CreateRetVoid();
  } else {
    builder.CreateRet(opVal);
  }
}

static void emitRecoveryPath(BasicBlock *block, Function *wrapperFn,
                             RemediationStrategies policy) {
  Module *M = wrapperFn->getParent();
  LLVMContext &Ctx = wrapperFn->getContext();
  IRBuilder<> builder(Ctx);

  builder.SetInsertPoint(block);
  builder.CreateCall(getOrCreateRemediationBehavior(M, policy));
  builder.CreateUnreachable();
}

static Function *getOrCreateContractWrapper(Module *M, CallInst *call,
                                            Contract contract,
                                            RemediationStrategies policy) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  Function *originalFn = call->getCalledFunction();

  std::string handlerName = "__cve_contract_" + originalFn->getName().str();

  FunctionType *wrapperTy = originalFn->getFunctionType();

  Function *resolveWrapperFn =
      getOrCreateResolveHelper(M, handlerName, wrapperTy);

  if (!resolveWrapperFn->empty()) {
    recordPatchFunction(resolveWrapperFn);
    return resolveWrapperFn;
  }

  // TODO: Create 3 basic blocks
  // 1. Preconditions
  // 2. Valid path
  // 3. Recovery path
  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveWrapperFn);
  BasicBlock *ValidBB = BasicBlock::Create(Ctx, "valid.path", resolveWrapperFn);
  BasicBlock *RecoverBB =
      BasicBlock::Create(Ctx, "recover.path", resolveWrapperFn);

  // TODO: Create helper to generate the llvm-ir for preconditions
  emitPreconditions(resolveWrapperFn, EntryBB, ValidBB, RecoverBB, contract);

  // TODO: Create helper to generate valid path (call original operation
  // contract)
  emitValidPath(ValidBB, resolveWrapperFn, originalFn);

  // TODO: Create helper to generate recovery path
  emitRecoveryPath(RecoverBB, resolveWrapperFn, policy);

  validateIR(resolveWrapperFn);
  recordPatchFunction(resolveWrapperFn);
  return resolveWrapperFn;
}

void sanitizeContract(Function *F, Contract contract,
                      RemediationStrategies policy) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<CallInst *> callsToReplace;
  std::string opName = contract.operation;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();
        if (!calledFn) {
          continue;
        }

        StringRef calledFnName = calledFn->getName();
        if (calledFnName == opName) {
          callsToReplace.push_back(call);
        }
      }
    }
  }

  if (callsToReplace.size() == 0) {
    return;
  }

  Function *resolveWrapperFn =
      getOrCreateContractWrapper(M, callsToReplace.front(), contract, policy);

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
