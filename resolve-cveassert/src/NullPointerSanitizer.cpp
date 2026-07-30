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
getOrCreateNullPtrLoadSanitizer(Function *F, Type *valueType,
                                Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__resolve_null_check_ld_" + getLLVMType(valueType);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptrType = PointerType::get(Ctx, 0);
  auto pointerIntType = Type::getInt64Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *wrapperType = FunctionType::get(valueType, {ptrType}, false);
  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkNullPtrBB = BasicBlock::Create(Ctx, "check.null", wrapperFn);
  BasicBlock *handleNullPtrBB =
      BasicBlock::Create(Ctx, "sanitize.load", wrapperFn);
  BasicBlock *performLoadBB = BasicBlock::Create(Ctx, "safe.load", wrapperFn);

  builder.SetInsertPoint(entryBB);
  Argument *ptr = wrapperFn->getArg(0);
  createSanitizerGateBranch(builder, F, 1, performLoadBB, checkNullPtrBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  builder.SetInsertPoint(checkNullPtrBB);
  Value *ptrAsInt = builder.CreatePtrToInt(ptr, pointerIntType);
  Value *isBelowMinAddress =
      builder.CreateICmpULT(ptrAsInt, ConstantInt::get(pointerIntType, 0x1000));

  builder.CreateCondBr(isBelowMinAddress, handleNullPtrBB, performLoadBB);

  builder.SetInsertPoint(handleNullPtrBB);
  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE:
    builder.CreateRet(Constant::getNullValue(valueType));
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

  builder.SetInsertPoint(performLoadBB);
  Value *loadedValue = builder.CreateLoad(valueType, ptr);
  builder.CreateRet(loadedValue);

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *getOrCreateNullPtrStoreSanitizer(
    Function *F, Type *valueType,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__resolve_null_check_st_" + getLLVMType(valueType);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptrType = PointerType::get(Ctx, 0);
  auto pointerIntType = Type::getInt64Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *wrapperType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptrType, valueType}, false);
  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkNullPtrBB = BasicBlock::Create(Ctx, "check.null", wrapperFn);
  BasicBlock *handleNullPtrBB =
      BasicBlock::Create(Ctx, "sanitize.store", wrapperFn);
  BasicBlock *performStoreBB = BasicBlock::Create(Ctx, "safe.store", wrapperFn);

  // Set insertion point to entry block
  builder.SetInsertPoint(entryBB);
  Argument *ptr = wrapperFn->getArg(0);
  Argument *storedValue = wrapperFn->getArg(1);
  createSanitizerGateBranch(builder, F, 1, performStoreBB, checkNullPtrBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  // Updating conditional check for ptr value less than 0x1000
  // Unix systems do not map first page of memory,
  // we need to detect remdiate pointers within this range.
  builder.SetInsertPoint(checkNullPtrBB);
  Value *ptrAsInt = builder.CreatePtrToInt(ptr, pointerIntType);
  Value *isBelowMinAddress =
      builder.CreateICmpULT(ptrAsInt, ConstantInt::get(pointerIntType, 0x1000));
  builder.CreateCondBr(isBelowMinAddress, handleNullPtrBB, performStoreBB);

  builder.SetInsertPoint(handleNullPtrBB);
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
  builder.SetInsertPoint(performStoreBB);
  builder.CreateStore(storedValue, ptr);
  builder.CreateRetVoid();

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

void sanitizeNullPointers(Function *F,
                          Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  SmallVector<LoadInst *> loadList;
  SmallVector<StoreInst *> storeList;

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
    for (auto &inst : BB) {
      if (auto *load = dyn_cast<LoadInst>(&inst)) {
        loadList.push_back(load);
      } else if (auto *store = dyn_cast<StoreInst>(&inst)) {
        storeList.push_back(store);
      }
    }
  }

  for (auto *load : loadList) {
    builder.SetInsertPoint(load);
    auto valueType = load->getType();

    auto loadFn = getOrCreateNullPtrLoadSanitizer(F, valueType, strategy);

    auto sanitizedLoad =
        builder.CreateCall(loadFn, {load->getPointerOperand()});
    load->replaceAllUsesWith(sanitizedLoad);
    load->removeFromParent();
    load->deleteValue();
  }

  for (auto *store : storeList) {
    builder.SetInsertPoint(store);
    auto valueType = store->getValueOperand()->getType();
    auto storeFn = getOrCreateNullPtrStoreSanitizer(F, valueType, strategy);

    auto sanitizedStore = builder.CreateCall(
        storeFn, {store->getPointerOperand(), store->getValueOperand()});
    store->replaceAllUsesWith(sanitizedStore);
    store->removeFromParent();
    store->deleteValue();
  }
}
