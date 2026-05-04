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
    CallInst *resolveCall = builder.CreateCall(resolveCallee, args);

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
  // Initialize list to store pointers to alloca and instructions
  std::vector<AllocaInst *> toFreeList;

  auto allocateFn = M->getOrInsertFunction(
      "__resolve_alloca", FunctionType::get(void_ty, {ptr_ty, size_ty}, false));
  auto invalidateFn =
      M->getOrInsertFunction("__resolve_invalidate_stack",
                             FunctionType::get(void_ty, {ptr_ty}, false));

  auto compute_alloca_size = [&](auto *allocaInst, Type *allocType) -> Value * {
    // works for both dynamic and static allocas
    // size of one element
    uint64_t elemSize = DL.getTypeAllocSize(allocType);
    Value *elemSizeVal = ConstantInt::get(size_ty, elemSize);

    // number of elements
    // getArraySize returns the number of elements, not size in bytes
    Value *arraySize = allocaInst->getArraySize();

    // convert arraySize to size_ty for multiplication
    if (arraySize->getType() != size_ty) {
      arraySize = builder.CreateZExt(arraySize, size_ty);
    }

    // totalSize = (# of elements) * (size of element in bytes)
    Value *totalSize = builder.CreateMul(elemSizeVal, arraySize);
    return totalSize;
  };

  auto handle_alloca = [&](auto *allocaInst) {
    Value *totalSize;
    Type *allocatedType = allocaInst->getAllocatedType();
    // Compute the size of the alloca
    // if the size of the alloca is known at compile-time then use it
    // otherwise call compute_alloca_size
    if (auto maybeSize = allocaInst->getAllocationSize(DL)) {
      TypeSize ts = *maybeSize;
      uint64_t size = ts.getFixedValue();
      totalSize = ConstantInt::get(size_ty, size);
    } else {
      totalSize = compute_alloca_size(allocaInst, allocatedType);
    }

    // Build the new alloca
    // %new_ptr = alloca n + 1
    // call void __resolve_alloca(old_ptr, n)
    // %ptr = alloca n
    // alloca n + 1
    // __resolve_alloca ptr , sizeof()
    builder.SetInsertPoint(allocaInst);
    Value *rawSize = builder.CreateAdd(totalSize, ConstantInt::get(size_ty, 1));
    AllocaInst *rawAlloca =
        builder.CreateAlloca(allocaInst->getAllocatedType(), rawSize);

    rawAlloca->setAlignment(allocaInst->getAlign());
    rawAlloca->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));

    // Cast back to original type
    Value *typedPtr = builder.CreateBitCast(rawAlloca, ptr_ty);
    if (auto *inst = dyn_cast<Instruction>(typedPtr)) {
      inst->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
    }

    bool hasStart = false;
    bool hasEnd = false;
    SmallVector<IntrinsicInst *, 8> lifetimeStarts;
    SmallVector<IntrinsicInst *, 8> lifetimeEnds;
    for (auto *user : allocaInst->users()) {
      if (auto *ii = dyn_cast<IntrinsicInst>(user)) {
        if (ii->getIntrinsicID() == Intrinsic::lifetime_start) {
          lifetimeStarts.push_back(ii);
          hasStart = true;
        } else if (ii->getIntrinsicID() == Intrinsic::lifetime_end) {
          lifetimeEnds.push_back(ii);
          hasEnd = true;
        }
      }
    }

    if (hasStart) {
      for (auto *ii : lifetimeStarts) {
        builder.SetInsertPoint(ii->getNextNode());
        builder.CreateCall(allocateFn, {typedPtr, rawSize});
        ii->setOperand(0, rawSize);
        ii->setOperand(1, typedPtr);
      }
    } else {
      builder.CreateCall(allocateFn, {typedPtr, rawSize});
    }

    if (hasEnd) {
      for (auto *ii : lifetimeEnds) {
        builder.SetInsertPoint(ii->getNextNode());
        builder.CreateCall(invalidateFn, {typedPtr});
        ii->setOperand(1, typedPtr);
      }
    } else {
      toFreeList.push_back(rawAlloca);
    }

    allocaInst->replaceAllUsesWith(typedPtr);
    allocaInst->eraseFromParent();
  };

  // proposing new padding logic
  // increasing array size by 1 of alloca by sizeof(elemType)
  // if array size is constant int then we need to replace it with constant + 1
  // to look like static alloca no control flow in handle_alloca its increases
  // allocas are implicitly arrays even allocas with of size 1
  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
        allocas.push_back(inst);
      }
    }
  }

  // We want our instrumentation to reflect llvm lifetime view
  // (so we dont break optimizations)

  for (auto *alloca : allocas) {
    // Fast filter to prune non-escaping allocas
    // if (PointerMayBeCaptured(alloca, true, true)) {
    // NOTE: Skip allocas that contain a single value
    Type *allocatedType = alloca->getAllocatedType();
    if (allocatedType->isSingleValue()) {
      continue;
    }
    handle_alloca(alloca);
    //}
  }

  if (toFreeList.empty()) {
    return;
  }

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<ReturnInst>(&instr)) {
        builder.SetInsertPoint(inst);
        for (auto *padded : toFreeList) {
          builder.CreateCall(invalidateFn, {padded});
        }
      }
    }
  }
}
