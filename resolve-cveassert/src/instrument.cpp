/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <utility>

#include "helpers.hpp"

using namespace llvm;

/// Replaces all calls to `name` in `F` with calls to `__resolve_name`
static void wrapLibraryFunction(Function *F, StringRef name, FunctionType *ty) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  SmallVector<CallInst *, 8> callList;

  SmallString<16> resolveCalleeName = {"__resolve_", name};
  FunctionCallee resolveCallee = M->getOrInsertFunction(resolveCalleeName, ty);

  auto swap_call = [&](CallInst *callInst) {
    builder.SetInsertPoint(callInst);
    SmallVector<Value *, 8> args(callInst->arg_begin(), callInst->arg_end());
    CallInst *resolveCall = builder.CreateCall(
        resolveCallee, args, callInst->getName() + ".instrumented");

    callInst->replaceAllUsesWith(resolveCall);
    callInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (calledFn && calledFn->getName() == name) {
          callList.push_back(call);
        }
      }
    }
  }

  for (auto call : callList) {
    swap_call(call);
  }
}

void instrumentLibraryAllocations(Function *F) {
  LLVMContext &Ctx = F->getContext();

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  wrapLibraryFunction(F, "malloc", FunctionType::get(ptr_ty, {size_ty}, false));
  wrapLibraryFunction(F, "realloc",
                      FunctionType::get(ptr_ty, {ptr_ty, size_ty}, false));
  wrapLibraryFunction(F, "calloc",
                      FunctionType::get(ptr_ty, {size_ty, size_ty}, false));
  wrapLibraryFunction(F, "free", FunctionType::get(void_ty, {ptr_ty}, false));
  wrapLibraryFunction(F, "strdup", FunctionType::get(ptr_ty, {ptr_ty}, false));
  wrapLibraryFunction(F, "strndup",
                      FunctionType::get(ptr_ty, {ptr_ty, size_ty}, false));
}

void instrumentAlloca(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  SmallVector<AllocaInst *, 16> allocas;
  SmallVector<AllocaInst *, 16> toFreeList;

  auto allocateFn = M->getOrInsertFunction(
      "__resolve_alloca", FunctionType::get(void_ty, {ptr_ty, size_ty}, false));
  auto invalidateFn =
      M->getOrInsertFunction("__resolve_invalidate_stack",
                             FunctionType::get(void_ty, {ptr_ty}, false));

  // 2 cases
  // 1. alloca [N x T]
  // 2. alloca T, i64 N where N is constant
  auto create_transformed_array_alloca = [&](auto *oldAlloca) -> AllocaInst * {
    builder.SetInsertPoint(oldAlloca->getNextNode());
    ArrayType *arrTy = dyn_cast<ArrayType>(oldAlloca->getAllocatedType());
    uint64_t numElements = arrTy->getNumElements();
    Type *elemTy = arrTy->getElementType();
    uint64_t size = numElements + 1;
    ArrayType *newArrayTy = ArrayType::get(elemTy, size);
    AllocaInst *transformedAlloca = builder.CreateAlloca(
        newArrayTy, nullptr, oldAlloca->getName() + ".instrumented");
    transformedAlloca->setAlignment(oldAlloca->getAlign());
    return transformedAlloca;
  };

  auto create_transformed_alloca =
      [&](auto *oldAlloca) -> std::pair<AllocaInst *, Value *> {
    builder.SetInsertPoint(oldAlloca->getNextNonDebugInstruction());
    Value *arrSize = oldAlloca->getArraySize();
    Type *oldAllocaTy = oldAlloca->getAllocatedType();
    Value *updatedSize =
        builder.CreateAdd(arrSize, ConstantInt::get(size_ty, 1));
    AllocaInst *transformedAlloca = builder.CreateAlloca(
        oldAllocaTy, updatedSize, oldAlloca->getName() + ".instrumented");
    transformedAlloca->setAlignment(oldAlloca->getAlign());
    return {transformedAlloca, updatedSize};
  };

  auto handle_alloca = [&](auto *allocaInst) {
    Value *totalSize;
    AllocaInst *transformedAlloca;
    Type *allocatedType = allocaInst->getAllocatedType();

    if (isa<ArrayType>(allocatedType)) {
      transformedAlloca = create_transformed_array_alloca(allocaInst);
      auto maybeSize = allocaInst->getAllocationSize(DL);
      TypeSize ts = *maybeSize;
      uint64_t size = ts.getFixedValue();
      totalSize = ConstantInt::get(size_ty, size);
    } else {
      auto result = create_transformed_alloca(allocaInst);
      transformedAlloca = result.first;
      totalSize = result.second;
    }

    transformedAlloca->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));

    // Because instrumenation alters the effective size of stack allocation
    // we need to rewrite intrinsics to reflect instrumented size
    SmallVector<IntrinsicInst *, 16> lifetimeStart;
    SmallVector<IntrinsicInst *, 16> lifetimeEnd;

    bool hasStart = false;
    bool hasEnd = false;
    for (auto *user : allocaInst->users()) {
      if (auto *ii = dyn_cast<IntrinsicInst>(user)) {
        Intrinsic::ID id = ii->getIntrinsicID();
        if (id == Intrinsic::lifetime_start) {
          hasStart = true;
          lifetimeStart.push_back(ii);
        }

        if (id == Intrinsic::lifetime_end) {
          hasEnd = true;
          lifetimeEnd.push_back(ii);
        }
      }
    }

    for (auto *ii : lifetimeStart) {
      ii->setArgOperand(0, totalSize);
      builder.SetInsertPoint(ii->getNextNode());
      builder.CreateCall(allocateFn, {transformedAlloca, totalSize});
    }

    for (auto *ii : lifetimeEnd) {
      ii->setArgOperand(0, totalSize);
      builder.SetInsertPoint(ii->getNextNode());
      builder.CreateCall(invalidateFn, {transformedAlloca});
    }

    // Well-formed LLVM-IR may not have
    // lifetime.start or lifetime.end instructions
    if (!hasStart) {
      builder.SetInsertPoint(transformedAlloca->getNextNode());
      builder.CreateCall(allocateFn, {transformedAlloca, totalSize});
    }

    if (!hasEnd) {
      toFreeList.push_back(transformedAlloca);
    }

    allocaInst->replaceAllUsesWith(transformedAlloca);
    // dumpAllocaTransfrom(allocaInst, transformedAlloca);
  };

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
        allocas.push_back(inst);
      }
    }
  }

  for (auto *alloca : allocas) {
    Type *allocatedType = alloca->getAllocatedType();
    bool isStaticArray = isa<ArrayType>(allocatedType);
    bool isDynamicArray = alloca->isArrayAllocation();

    if (!isStaticArray && !isDynamicArray) {
      continue;
    }

    // TODO: Add fast filter to prune non-escaping allocas
    handle_alloca(alloca);
  }

  if (toFreeList.empty()) {
    return;
  }

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<ReturnInst>(&instr)) {
        builder.SetInsertPoint(inst);
        for (auto *alloca : toFreeList) {
          builder.CreateCall(invalidateFn, {alloca});
        }
      }
    }
  }

  for (auto *alloca : allocas) {
    if (alloca->use_empty()) {
      alloca->eraseFromParent();
    }
  }

  // [DEBUGGING]
  if (F->getName() == "bn_mod_exp_mont_fixed_top") {
    validateIR(F);
  }
  // validateIR(F);
}
