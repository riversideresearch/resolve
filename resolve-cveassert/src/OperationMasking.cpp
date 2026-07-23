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

  Value *Cond = nullptr;

  // Fetch wrapper argument idx
  Argument *arg = wrapperFn->getArg(precond.arg0);

  // Check the predicate
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

static Function *getOrCreateContractWrapper(Function *F, CallInst *call,
                                            Contract contract,
                                            RemediationStrategies policy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  Function *originalFn = call->getCalledFunction();

  std::string handlerName = "__cve_contract_" + originalFn->getName().str();

  FunctionType *wrapperTy = originalFn->getFunctionType();

  Function *wrapperFn =
      getOrCreateResolveHelper(F->getParent(), handlerName, wrapperTy);

  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
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

  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  smallVectory<CallInst *> matchingCalls;
  std::string operationName = contract.operation;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *callee = call->getCalledFunction();
        if (!callee) {
          continue;
        }

        StringRef calleeName = callee->getName();
        if (calleeName == operationName) {
          matchingCalls.push_back(call);
        }
      }
    }
  }

  if (matchingCalls.size() == 0) {
    return;
  }

  Function *contractWrapperFn =
      getOrCreateContractWrapper(F, matchingCalls.front(), contract, policy);

  for (auto call : matchingCalls) {
    builder.SetInsertPoint(call);
    SmallVector<Value *, 2> callArgs;
    for (unsigned int i = 0; i < call->arg_size(); ++i) {
      callArgs.push_back(call->getOperand(i));
    }

    auto wrapperCall = builder.CreateCall(contractWrapperFn, callArgs);
    call->replaceAllUsesWith(wrapperCall);
    call->eraseFromParent();
  }
}
