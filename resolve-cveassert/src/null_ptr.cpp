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
#include "Vulnerability.hpp"
#include "helpers.hpp"

using namespace llvm;

static Function *
getOrCreateNullPtrLoadSanitizer(Function *F, Type *ty,
                                Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_sanitize_null_ptr_ld_" + getLLVMType(ty);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  GlobalVariable *map = SanitizerMaps[F];

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *resolveNullPtrLdFnTy = FunctionType::get(ty, {ptr_ty}, false);
  Function *resolveNullPtrLdFn = getOrCreateResolveHelper(M, handlerName, resolveNullPtrLdFnTy);
  if (!resolveNullPtrLdFn->empty()) { return resolveNullPtrLdFn; }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveNullPtrLdFn);
  BasicBlock *CheckIfNullBB = BasicBlock::Create(Ctx, "check_if_null", resolveNullPtrLdFn);
  BasicBlock *SanitizeNullPtrBB = BasicBlock::Create(Ctx,"sanitize_null_ptr", resolveNullPtrLdFn);
  BasicBlock *NormalLoadBB = BasicBlock::Create(Ctx, "safe_load", resolveNullPtrLdFn);

  builder.SetInsertPoint(EntryBB);
  Argument *inputPtr = resolveNullPtrLdFn->getArg(0);
  Value *zero = builder.getInt64(0);
  Value *mapPtr = builder.CreateGEP(
    map->getValueType(),
    map,
    { zero, zero }
  );

  Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M), { mapPtr, ConstantInt::get(usize_ty, 1)});
  Value *isZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalLoadBB, CheckIfNullBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  builder.SetInsertPoint(CheckIfNullBB);
  Value *PtrValue = builder.CreatePtrToInt(inputPtr, usize_ty);
  Value *IsNull =
      builder.CreateICmpULT(PtrValue, ConstantInt::get(usize_ty, 0x1000));

  builder.CreateCondBr(IsNull, SanitizeNullPtrBB, NormalLoadBB);

  builder.SetInsertPoint(SanitizeNullPtrBB);
  FunctionType *logMemInstFuncTy = FunctionType::get(void_ty, {ptr_ty}, false);
  FunctionCallee logMemInstFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", logMemInstFuncTy);
  builder.CreateCall(logMemInstFunc, { inputPtr });

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE: {
    builder.CreateRet(Constant::getNullValue(ty));
    break;
  }

  default:
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    builder.CreateUnreachable();
    break;
  }

  builder.SetInsertPoint(NormalLoadBB);
  Value *ld = builder.CreateLoad(ty, inputPtr);
  builder.CreateRet(ld);

  validateIR(resolveNullPtrLdFn);
  return resolveNullPtrLdFn;
}

static Function *getOrCreateNullPtrStoreSanitizer(
    Function *F, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_sanitize_null_ptr_st_" + getLLVMType(ty);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  GlobalVariable *map = SanitizerMaps[F];

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *resolveNullPtrStFnTy =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty, ty}, false);
  Function *resolveNullPtrStFn = getOrCreateResolveHelper(M, handlerName, resolveNullPtrStFnTy);
  if (!resolveNullPtrStFn->empty()) { return resolveNullPtrStFn; }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveNullPtrStFn);
  BasicBlock *CheckIfNullBB = BasicBlock::Create(Ctx, "check_if_null", resolveNullPtrStFn);
  BasicBlock *SanitizeNullPtrBB = BasicBlock::Create(Ctx, "sanitize_null_ptr", resolveNullPtrStFn);
  BasicBlock *NormalStoreBB = BasicBlock::Create(Ctx, "safe_store", resolveNullPtrStFn);

  // Set insertion point to entry block
  builder.SetInsertPoint(EntryBB);
  Argument *inputPtr = resolveNullPtrStFn->getArg(0);
  Argument *inputValue = resolveNullPtrStFn->getArg(1);
  Value *mapPtr = builder.CreateGEP(
    map->getValueType(),
    map,
    { builder.getInt64(0), builder.getInt64(0) }
  );

  Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M), { mapPtr, ConstantInt::get(usize_ty, 1)});
  Value *isZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalStoreBB, CheckIfNullBB);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  // Updating conditional check for ptr value less than 0x1000
  // Unix systems do not map first page of memory,
  // we need to detect remdiate pointers within this range.
  builder.SetInsertPoint(CheckIfNullBB);
  Value *PtrValue = builder.CreatePtrToInt(inputPtr, usize_ty);
  Value *IsNull =
      builder.CreateICmpULT(PtrValue, ConstantInt::get(usize_ty, 0x1000));
  builder.CreateCondBr(IsNull, SanitizeNullPtrBB, NormalStoreBB);

  builder.SetInsertPoint(SanitizeNullPtrBB);
  FunctionType *logMemInstFuncTy = FunctionType::get(void_ty, {ptr_ty}, false);
  FunctionCallee logMemInstFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", logMemInstFuncTy);
  builder.CreateCall(logMemInstFunc, {inputPtr});

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE: {
    builder.CreateRetVoid();
    break;
  }

  default:
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    builder.CreateUnreachable();
    break;
  }

  // Return Block: returns pointer if non-null
  builder.SetInsertPoint(NormalStoreBB);
  builder.CreateStore(inputValue, inputPtr);
  builder.CreateRetVoid();

  validateIR(resolveNullPtrStFn);
  return resolveNullPtrStFn;
}

void sanitizeNullPointers(Function *F,
                          Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
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

    auto loadFn = getOrCreateNullPtrLoadSanitizer(
        F, valueTy, strategy);

    auto sanitizedLoad =
        builder.CreateCall(loadFn, {Inst->getPointerOperand()});
    Inst->replaceAllUsesWith(sanitizedLoad);
    Inst->removeFromParent();
    Inst->deleteValue();
  }

  for (auto Inst : storeList) {
    builder.SetInsertPoint(Inst);
    auto valueTy = Inst->getValueOperand()->getType();
    auto storeFn = getOrCreateNullPtrStoreSanitizer(
        F, valueTy, strategy);

    auto sanitizedStore = builder.CreateCall(
        storeFn, {Inst->getPointerOperand(), Inst->getValueOperand()});
    Inst->replaceAllUsesWith(sanitizedStore);
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}
