/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"

#include "IRUtils.hpp"
#include "Vulnerability.hpp"
#include "IRUtils.hpp"

using namespace llvm;

Function *getOrCreateIsHeap(Function *F) {
  auto *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *cveIsHeapFnTy = FunctionType::get(i1_ty, {ptr_ty}, false);
  Function *cveIsHeapFn =
      getOrCreateResolveHelper(M, "__cve_is_heap", cveIsHeapFnTy);

  if (!cveIsHeapFn->empty()) {
    return cveIsHeapFn;
  }

  IRBuilder<> builder(Ctx);
  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", cveIsHeapFn);
  builder.SetInsertPoint(entryBB);

  Argument *inputPtr = cveIsHeapFn->getArg(0);

  FunctionType *asmTy = FunctionType::get(ptr_ty, {});
  auto read_sp_asm = InlineAsm::get(asmTy, "mov %rsp, $0",
                                    "=r,~{dirflag},~{fpsr},~{flags}", true);
  auto read_sp = builder.CreateCall(read_sp_asm, {});

  // $rsp <= inputPtr
  auto is_stack = builder.CreateICmpULE(read_sp, inputPtr);

  auto start = M->getOrInsertGlobal("_start", Type::getInt8Ty(Ctx));
  auto end = M->getOrInsertGlobal("_end", Type::getInt8Ty(Ctx));

  // inputPtr >= _start && inputPtr <= _end
  auto is_static = builder.CreateAnd({
      builder.CreateICmpUGE(inputPtr, start),
      builder.CreateICmpULE(inputPtr, end),
  });

  // return !(is_stack || is_static)
  auto result = builder.CreateNot(builder.CreateOr(is_stack, is_static));
  builder.CreateRet(result);

  validateIR(cveIsHeapFn);
  return cveIsHeapFn;
}

Function *getOrCreateFreeOfNonHeapSanitizer(
    Function *F, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "__cve_nonheap_free";
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  GlobalVariable *map = SanitizerMaps[F];

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *cveFreeNonHeapFnTy =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
  Function *cveFreeNonHeapFn =
      getOrCreateResolveHelper(M, handlerName, cveFreeNonHeapFnTy);
  if (!cveFreeNonHeapFn->empty()) {
    return cveFreeNonHeapFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", cveFreeNonHeapFn);
  BasicBlock *CheckOnHeapBB =
      BasicBlock::Create(Ctx, "check.heap", cveFreeNonHeapFn);
  BasicBlock *SanitizeNonHeapBB =
      BasicBlock::Create(Ctx, "sanitize.nonheap", cveFreeNonHeapFn);
  BasicBlock *FreeHeapBB =
      BasicBlock::Create(Ctx, "free.heap", cveFreeNonHeapFn);

  // Set insertion point to entry block
  builder.SetInsertPoint(EntryBB);
  Argument *inputPtr = cveFreeNonHeapFn->getArg(0);

  Value *mapPtr = builder.CreateGEP(map->getValueType(), map,
                                    {builder.getInt64(0), builder.getInt64(0)});
  Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M),
                                       {mapPtr, ConstantInt::get(usize_ty, 2)});
  Value *isZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, FreeHeapBB, CheckOnHeapBB);

  // Call Is Heap Func
  // Branch if True
  builder.SetInsertPoint(CheckOnHeapBB);
  Value *IsHeap = builder.CreateCall(getOrCreateIsHeap(F), {inputPtr});
  builder.CreateCondBr(IsHeap, FreeHeapBB, SanitizeNonHeapBB);

  builder.SetInsertPoint(SanitizeNonHeapBB);
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
  }
  builder.CreateRetVoid();

  // Free Block: call Free
  builder.SetInsertPoint(FreeHeapBB);
  builder.CreateCall(M->getFunction("free"), {inputPtr});
  builder.CreateRetVoid();

  validateIR(cveFreeNonHeapFn);
  return cveFreeNonHeapFn;
}

void sanitizeFreeOfNonHeap(Function *F,
                           Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> workList;

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
