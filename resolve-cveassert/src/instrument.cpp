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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

static void dumpAllocaTransfrom(AllocaInst *preAlloca, AllocaInst *postAlloca) {
  errs() << "=== Alloca Transform ===\n";
  errs() << "Original alloca:\n";
  preAlloca->dump();

  errs() << "Allocated type: ";
  preAlloca->getAllocatedType()->print(errs());
  errs() << "\n";

  errs() << "Array size: ";
  preAlloca->getArraySize()->print(errs());
  errs() << "\n";

  errs() << "\nTransformed Alloca:\n";
  postAlloca->dump();

  errs() << "Allocated type: ";
  postAlloca->getAllocatedType()->print(errs());
  errs() << "\n";

  errs() << "Array size: ";
  preAlloca->getArraySize()->print(errs());
  errs() << "\n";
  errs() << "\n=======================\n";
}

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

  raw_ostream &out = llvm::errs();

  auto allocateFn = M->getOrInsertFunction(
      "__resolve_alloca", FunctionType::get(void_ty, {ptr_ty, size_ty}, false));
  auto invalidateFn =
      M->getOrInsertFunction("__resolve_invalidate_stack",
                             FunctionType::get(void_ty, {ptr_ty}, false));

  auto create_transformed_array_alloca = [&](auto *oldAlloca) -> AllocaInst * {
    builder.SetInsertPoint(oldAlloca->getNextNode());

    Type *oldAllocaTy = oldAlloca->getAllocatedType();
    auto *arrTy = dyn_cast<ArrayType>(oldAllocaTy);
    uint64_t numElements = arrTy->getNumElements();
    Type *elemTy = arrTy->getElementType();
    uint64_t updatedSize = numElements + 1;
    ArrayType *newArrayTy = ArrayType::get(elemTy, updatedSize);
    AllocaInst *transformedAlloca = builder.CreateAlloca(newArrayTy);
    transformedAlloca->setAlignment(oldAlloca->getAlign());
    return transformedAlloca;
  };

  auto create_transformed_dynamic_alloca = [&](auto *oldAlloca, Value *originalSize) -> AllocaInst * {
    builder.SetInsertPoint(oldAlloca->getNextNode());

    Type *oldAllocaTy = oldAlloca->getAllocatedType();
    Value *updatedSize = builder.CreateAdd(originalSize, ConstantInt::get(size_ty, 1));
    AllocaInst *transformedAlloca = builder.CreateAlloca(oldAllocaTy, updatedSize);
    transformedAlloca->setAlignment(oldAlloca->getAlign());
    return transformedAlloca;
  };

  auto handle_alloca = [&](auto *allocaInst) {
    Value *totalSize;
    AllocaInst *transformedAlloca;

    // Compute the size of the alloca
    // if the size of the alloca is known at compile-time then use it
    // otherwise call compute_alloca_size
    if (auto maybeSize = allocaInst->getAllocationSize(DL)) {
      TypeSize ts = *maybeSize;
      uint64_t size = ts.getFixedValue();
      totalSize = ConstantInt::get(size_ty, size);
      transformedAlloca = create_transformed_array_alloca(allocaInst);
    
    } else {
      totalSize = allocaInst->getArraySize();
      transformedAlloca = create_transformed_dynamic_alloca(allocaInst, totalSize);
    }

    transformedAlloca->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
    // llvm.lifetime_start(ptr %newAlloca, i64 %newSize)
    // llvm.lifetime_end(ptr %newAlloca, i64 %newSize)
    // update the size for the life time
    SmallVector<IntrinsicInst*, 16> lifetimeStart;
    SmallVector<IntrinsicInst*, 16> lifetimeEnd;

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

    // Not all well-formed llvm-ir will emit both 
    // llvm.lifetime_start and llvm.lifetime_end
    if (!hasStart) {
      builder.SetInsertPoint(allocaInst->getNextNode());
      builder.CreateCall(allocateFn, {transformedAlloca, totalSize});
    }

    if (!hasEnd) {
      toFreeList.push_back(transformedAlloca);
    }

    // DEBUGGING
    // for (User *user : allocaInst->users()) {
    //   errs() << "User:\n";
    //   user->dump();
    // }

    allocaInst->replaceAllUsesWith(transformedAlloca);
    allocaInst->eraseFromParent();
    //dumpAllocaTransfrom(allocaInst, transformedAlloca);
  };

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
    if (allocatedType->isSingleValueType() && alloca->isStaticAlloca()) {
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
        for (auto *alloca : toFreeList) {
          builder.CreateCall(invalidateFn, {alloca});
        }
      }
    }
  }
}
