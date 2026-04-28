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

  auto handle_alloca = [&](auto *allocaInst) {
    bool hasStart = false;
    bool hasEnd = false;

    Type *allocatedType = allocaInst->getAllocatedType();

    Value *arraySize = allocaInst->getArraySize();
    Value *totalSize;

    uint64_t elemSizeConst = DL.getTypeAllocSize(allocatedType);
    Value *elemSize = ConstantInt::get(size_ty, elemSizeConst);

    if (ConstantInt *CI = dyn_cast<ConstantInt>(arraySize)) {
      uint64_t n = CI->getZExtValue();
      totalSize = ConstantInt::get(size_ty, n * elemSizeConst);
    } else {
      totalSize = builder.CreateMul(arraySize, elemSize);
    }

    // Create padded alloca type
    builder.SetInsertPoint(allocaInst->getNextNode());
    StructType *paddedType =
        StructType::get(allocatedType, Type::getInt8Ty(Ctx));
    AllocaInst *paddedAlloca = builder.CreateAlloca(
        paddedType, nullptr, allocaInst->getName() + ".pad");
    paddedAlloca->setAlignment(allocaInst->getAlign());

    // Emit a gep instruction to point to allocated type
    Value *typedPtr = builder.CreateStructGEP(paddedType, paddedAlloca, 0);
    // NOTE: attaching metadata to gep instruction to prevent instrumentation of
    // gep
    if (auto *inst = dyn_cast<Instruction>(typedPtr)) {
      inst->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
    }

    // Collect lifetime calls
    SmallVector<Instruction *, 8> lifetimeCalls;

    for (auto *user : allocaInst->users()) {
      if (auto *call = dyn_cast<CallInst>(user)) {
        if (auto *intrinsic = dyn_cast<IntrinsicInst>(call)) {
          if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_start) {
            hasStart = true;
            lifetimeCalls.push_back(call);
          }

          if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_end) {
            hasEnd = true;
            lifetimeCalls.push_back(call);
          }
        }
      }
    }

    for (auto *call : lifetimeCalls) {
      if (auto *intrinsic = dyn_cast<IntrinsicInst>(call)) {
        if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_start) {
          builder.SetInsertPoint(call->getNextNode());
          builder.CreateCall(allocateFn, {typedPtr, totalSize});
          call->setOperand(1, typedPtr);
        }

        if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_end) {
          builder.SetInsertPoint(call->getNextNode());
          builder.CreateCall(invalidateFn, {allocaInst});
        }
      }
    }

    allocaInst->replaceAllUsesWith(typedPtr);

    // Instrument allocas that don't have lifetime markers
    // Not all llvm-ir produced hasStart == hasEnd
    if (!hasStart) {
      if (auto *inst = dyn_cast<Instruction>(allocaInst)) {
        builder.SetInsertPoint(inst->getNextNode());
        builder.CreateCall(allocateFn, {typedPtr, totalSize});
      }
    }

    if (!hasEnd) {
      toFreeList.push_back(allocaInst);
    }
  };

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
        allocas.push_back(inst);
      }
    }
  }

  for (auto *alloca : allocas) {
    // Fast filter to prune non-escaping allocas
    if (PointerMayBeCaptured(alloca, true, true)) {
      handle_alloca(alloca);
    }
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
