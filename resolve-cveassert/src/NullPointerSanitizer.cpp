/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include "CVEAssert.hpp"
#include "IRUtils.hpp"
#include "Vulnerability.hpp"

using namespace llvm;

static Function *
getOrCreateNullPtrLoadSanitizer(Function *F, Type *ty,
                                Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__resolve_null_check_ld_" + getLLVMType(ty);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *wrapperType = FunctionType::get(ty, {ptr_ty}, false);
  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *CheckIfNullBB = BasicBlock::Create(Ctx, "check.null", wrapperFn);
  BasicBlock *SanitizeNullPtrBB =
      BasicBlock::Create(Ctx, "sanitize.load", wrapperFn);
  BasicBlock *NormalLoadBB = BasicBlock::Create(Ctx, "safe.load", wrapperFn);

  builder.SetInsertPoint(EntryBB);
  Argument *inputPtr = wrapperFn->getArg(0);
  createSanitizerGateBranch(builder, F, 1, NormalLoadBB, CheckIfNullBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  builder.SetInsertPoint(CheckIfNullBB);
  Value *ptrAsInt = builder.CreatePtrToInt(inputPtr, usize_ty);
  Value *isBelowMinAddress =
      builder.CreateICmpULT(ptrAsInt, ConstantInt::get(usize_ty, 0x1000));

  builder.CreateCondBr(isBelowMinAddress, SanitizeNullPtrBB, NormalLoadBB);

  builder.SetInsertPoint(SanitizeNullPtrBB);
  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE:
    builder.CreateRet(Constant::getNullValue(ty));
    break;

  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
    builder.CreateCall(getOrCreateReportSanitizerTriggered(M));
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    builder.CreateUnreachable();
    break;

  default:
    llvm_unreachable("Not a supported strategy");
  }

  builder.SetInsertPoint(NormalLoadBB);
  Value *loadedValue = builder.CreateLoad(ty, inputPtr);
  builder.CreateRet(loadedValue);

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *getOrCreateNullPtrStoreSanitizer(
    Function *F, Type *ty, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__resolve_null_check_st_" + getLLVMType(ty);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *wrapperType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty, ty}, false);
  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperFnTy);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *CheckIfNullBB = BasicBlock::Create(Ctx, "check.null", wrapperFn);
  BasicBlock *SanitizeNullPtrBB =
      BasicBlock::Create(Ctx, "sanitize.store", wrapperFn);
  BasicBlock *NormalStoreBB = BasicBlock::Create(Ctx, "safe.store", wrapperFn);

  // Set insertion point to entry block
  builder.SetInsertPoint(EntryBB);
  Argument *inputPtr = wrapperFn->getArg(0);
  Argument *inputValue = wrapperFn->getArg(1);
  createSanitizerGateBranch(builder, F, 1, NormalStoreBB, CheckIfNullBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  // Updating conditional check for ptr value less than 0x1000
  // Unix systems do not map first page of memory,
  // we need to detect remdiate pointers within this range.
  builder.SetInsertPoint(CheckIfNullBB);
  Value *ptrAsInt = builder.CreatePtrToInt(inputPtr, usize_ty);
  Value *isBelowMinAddress =
      builder.CreateICmpULT(ptrAsInt, ConstantInt::get(usize_ty, 0x1000));
  builder.CreateCondBr(isBelowMinAddress, SanitizeNullPtrBB, NormalStoreBB);

  builder.SetInsertPoint(SanitizeNullPtrBB);
  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE:
    builder.CreateRetVoid();
    break;

  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
    builder.CreateCall(getOrCreateReportSanitizerTriggered(M));
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    builder.CreateUnreachable();
    break;

  default:
    llvm_unreachable("Not a supported strategy");
  }

  // Return Block: returns pointer if non-null
  builder.SetInsertPoint(NormalStoreBB);
  builder.CreateStore(inputValue, inputPtr);
  builder.CreateRetVoid();

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

void sanitizeNullPointers(Function *F,
                          Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<LoadInst *> loadList;
  std::vector<StoreInst *> storeList;

  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
  case Vulnerability::RemediationStrategies::CONTINUE:
    break;

  default:
    llvm::errs() << "[CVEAssert] Error: sanitizeNullPointers does not support "
                    "remediation strategy "
                 << "defaulting to continue strategy!\n";
    strategy = Vulnerability::RemediationStrategies::CONTINUE;
    break;
  }

  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (auto Inst = dyn_cast<LoadInst>(&I)) {
        loadList.push_back(Inst);
      } else if (auto Inst = dyn_cast<StoreInst>(&I)) {
        storeList.push_back(Inst);
      }
    }
  }

  for (auto Inst : loadList) {
    builder.SetInsertPoint(Inst);
    auto valueTy = Inst->getType();

    auto loadFn = getOrCreateNullPtrLoadSanitizer(F, valueTy, strategy);

    auto sanitizedLoad =
        builder.CreateCall(loadFn, {Inst->getPointerOperand()});
    Inst->replaceAllUsesWith(sanitizedLoad);
    Inst->removeFromParent();
    Inst->deleteValue();
  }

  for (auto Inst : storeList) {
    builder.SetInsertPoint(Inst);
    auto valueTy = Inst->getValueOperand()->getType();
    auto storeFn = getOrCreateNullPtrStoreSanitizer(F, valueTy, strategy);

    auto sanitizedStore = builder.CreateCall(
        storeFn, {Inst->getPointerOperand(), Inst->getValueOperand()});
    Inst->replaceAllUsesWith(sanitizedStore);
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}
