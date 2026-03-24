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

#include "Vulnerability.hpp"
#include "helpers.hpp"

using namespace llvm;

static Function *
getOrCreateNullPtrLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty,
                                Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_sanitize_null_ptr_ld_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName))
    return handler;

  IRBuilder<> Builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto int64_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *FuncType = FunctionType::get(ty, {ptr_ty}, false);
  Function *resolveNullPtrLdFn =
      Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", resolveNullPtrLdFn);
  BasicBlock *SanitizeBlock =
      BasicBlock::Create(Ctx, "sanitize_block", resolveNullPtrLdFn);
  BasicBlock *LoadBlock = BasicBlock::Create(Ctx, "load_block", resolveNullPtrLdFn);

  // Set insertion point to entry block
  Builder.SetInsertPoint(Entry);

  // Get function argument
  Argument *InputPtr = resolveNullPtrLdFn->getArg(0);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  Value *PtrValue = Builder.CreatePtrToInt(InputPtr, int64_ty);
  Value *IsNull =
      Builder.CreateICmpULT(PtrValue, ConstantInt::get(int64_ty, 0x1000));

  // Conditional branch
  Builder.CreateCondBr(IsNull, SanitizeBlock, LoadBlock);

  Builder.SetInsertPoint(SanitizeBlock);
  FunctionType *logMemInstFuncTy = FunctionType::get(void_ty, {ptr_ty}, false);
  FunctionCallee logMemInstFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", logMemInstFuncTy);
  Builder.CreateCall(logMemInstFunc, {InputPtr});

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE: {
    Builder.CreateRet(Constant::getNullValue(ty));
    break;
  }

  default:
    Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    Builder.CreateUnreachable();
    break;
  }

  // Return Block: returns pointer if non-null
  Builder.SetInsertPoint(LoadBlock);
  Value *ld = Builder.CreateLoad(ty, InputPtr);
  Builder.CreateRet(ld);

  resolveNullPtrLdFn->setMetadata("resolve.noinstrument", MDNode::get(Ctx, {}));

  validateFunctionIR(resolveNullPtrLdFn);
  return resolveNullPtrLdFn;
}

static Function *getOrCreateNullPtrStoreSanitizer(
    Module *M, LLVMContext &Ctx, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_sanitize_null_ptr_st_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName))
    return handler;

  IRBuilder<> Builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto int64_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *FuncType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty, ty}, false);
  Function *resolveNullPtrStFn =
      Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", resolveNullPtrStFn);
  BasicBlock *SanitizeBlock =
      BasicBlock::Create(Ctx, "sanitize_block", resolveNullPtrStFn);
  BasicBlock *StoreBlock = BasicBlock::Create(Ctx, "store_block", resolveNullPtrStFn);

  // Set insertion point to entry block
  Builder.SetInsertPoint(Entry);

  // Get function argument
  Argument *InputPtr = resolveNullPtrStFn->getArg(0);
  Argument *InputVal = resolveNullPtrStFn->getArg(1);

  // Compare pointer with null (opaque ptrs use generic ptr type)
  // TODO: Sanitize other invalid pointers
  // Updating conditional check for ptr value less than 0x1000
  // Unix systems do not map first page of memory,
  // we need to detect remdiate pointers within this range.
  Value *PtrValue = Builder.CreatePtrToInt(InputPtr, int64_ty);
  Value *IsNull =
      Builder.CreateICmpULT(PtrValue, ConstantInt::get(int64_ty, 0x1000));
  Builder.CreateCondBr(IsNull, SanitizeBlock, StoreBlock);

  Builder.SetInsertPoint(SanitizeBlock);
  FunctionType *logMemInstFuncTy = FunctionType::get(void_ty, {ptr_ty}, false);
  FunctionCallee logMemInstFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", logMemInstFuncTy);
  Builder.CreateCall(logMemInstFunc, {InputPtr});

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE: {
    Builder.CreateRetVoid();
    break;
  }

  default:
    Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    Builder.CreateUnreachable();
    break;
  }

  // Return Block: returns pointer if non-null
  Builder.SetInsertPoint(StoreBlock);
  Builder.CreateStore(InputVal, InputPtr);
  Builder.CreateRetVoid();


  resolveNullPtrStFn->setMetadata("resolve.noinstrument", MDNode::get(Ctx, {}));
  validateFunctionIR(resolveNullPtrStFn);
  return resolveNullPtrStFn;
}

void sanitizeNullPointers(Function *f,
                          Vulnerability::RemediationStrategies strategy) {
  IRBuilder<> builder(f->getContext());

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

  for (auto &BB : *f) {
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
        f->getParent(), f->getContext(), valueTy, strategy);

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
        f->getParent(), f->getContext(), valueTy, strategy);

    auto sanitizedStore = builder.CreateCall(
        storeFn, {Inst->getPointerOperand(), Inst->getValueOperand()});
    Inst->replaceAllUsesWith(sanitizedStore);
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}
