/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"

#include "IRUtils.hpp"
#include "Vulnerability.hpp"

using namespace llvm;

Function *getOrCreateIsHeap(Function *F) {
  auto *M = F->getParent();
  LLVMContext &Ctx = F->getContext();
  auto ptrType = PointerType::get(Ctx, 0);
  auto boolType = Type::getInt1Ty(Ctx);

  FunctionType *isHeapPtrFnType = FunctionType::get(boolType, {ptrType}, false);
  Function *isHeapPtrFn =
      getOrCreateResolveHelper(M, "__resolve_is_heap", isHeapPtrFnType);

  if (!isHeapPtrFn->empty()) {
    return isHeapPtrFn;
  }

  IRBuilder<> builder(Ctx);
  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", isHeapPtrFn);
  builder.SetInsertPoint(entryBB);

  Argument *ptr = isHeapPtrFn->getArg(0);

  FunctionType *asmType = FunctionType::get(ptrType, {});
  auto read_sp_asm = InlineAsm::get(asmType, "mov %rsp, $0",
                                    "=r,~{dirflag},~{fpsr},~{flags}", true);
  auto read_sp = builder.CreateCall(read_sp_asm, {});

  // $rsp <= ptr
  auto is_stack = builder.CreateICmpULE(read_sp, ptr);

  auto start = M->getOrInsertGlobal("_start", Type::getInt8Ty(Ctx));
  auto end = M->getOrInsertGlobal("_end", Type::getInt8Ty(Ctx));

  // ptr >= _start && ptr <= _end
  auto is_static = builder.CreateAnd({
      builder.CreateICmpUGE(ptr, start),
      builder.CreateICmpULE(ptr, end),
  });

  // return !(is_stack || is_static)
  auto result = builder.CreateNot(builder.CreateOr(is_stack, is_static));
  builder.CreateRet(result);

  validateIR(isHeapPtrFn);
  return isHeapPtrFn;
}

Function *getOrCreateFreeOfNonHeapSanitizer(
    Function *F, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__resolve_nonheap_free";
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  GlobalVariable *sanitizerMap = SanitizerMaps[F];

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptrType = PointerType::get(Ctx, 0);
  auto pointerIntegerType = Type::getInt64Ty(Ctx);
  auto boolType = Type::getInt1Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *sanitizerType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptrType}, false);
  Function *sanitizerFn =
      getOrCreateResolveHelper(M, handlerName, sanitizerType);
  if (!sanitizerFn->empty()) {
    return sanitizerFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", sanitizerFn);
  BasicBlock *checkHeapBB = BasicBlock::Create(Ctx, "check.heap", sanitizerFn);
  BasicBlock *handleInvalidFreeBB =
      BasicBlock::Create(Ctx, "sanitize.nonheap", sanitizerFn);
  BasicBlock *freeHeapBB = BasicBlock::Create(Ctx, "free.heap", sanitizerFn);

  // Set insertion point to entry block
  builder.SetInsertPoint(entryBB);
  Argument *ptr = sanitizerFn->getArg(0);

  createSanitizerGateBranch(builder, F, SanitizerFlag::FreeNonHeap, freeHeapBB,
                            checkHeapBB);

  builder.SetInsertPoint(checkHeapBB);
  Value *isHeapPtr = builder.CreateCall(getOrCreateIsHeap(F), {ptr});
  builder.CreateCondBr(isHeapPtr, freeHeapBB, handleInvalidFreeBB);

  builder.SetInsertPoint(handleInvalidFreeBB);
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
  }
  builder.CreateRetVoid();

  // Free Block: call Free
  builder.SetInsertPoint(freeHeapBB);
  builder.CreateCall(M->getFunction("free"), {ptr});
  builder.CreateRetVoid();

  validateIR(sanitizerFn);
  return sanitizerFn;
}

void sanitizeFreeOfNonHeap(Function *F,
                           Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  SmallVector<CallInst *> workList;

  for (auto &BB : *F) {
    for (auto &Inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&Inst)) {
        if (auto callee = call->getCalledFunction())
          if (callee->getName() == "free") {
            workList.push_back(call);
          }
      }
    }
  }

  for (auto call : workList) {
    builder.SetInsertPoint(call);
    auto sanitizerFn = getOrCreateFreeOfNonHeapSanitizer(F, strategy);

    builder.CreateCall(sanitizerFn, {call->getArgOperand(0)});
    call->removeFromParent();
    call->deleteValue();
  }
}
