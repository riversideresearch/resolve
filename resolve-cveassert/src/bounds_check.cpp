/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/raw_ostream.h"

#include "Vulnerability.hpp"
#include "helpers.hpp"

#include <map>
#include <unordered_set>

using namespace llvm;

static FunctionCallee getResolveBaseAndLimit(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto struct_ty = StructType::get(Ctx, {ptr_ty, ptr_ty}, false);

  MemoryEffects ME = MemoryEffects::none();

  AttrBuilder FnAttrs(Ctx);
  FnAttrs.addAttribute(Attribute::getWithMemoryEffects(Ctx, ME));
  FnAttrs.addAttribute(Attribute::WillReturn);
  FnAttrs.addAttribute(Attribute::Speculatable);

  AttributeList attrs =
      AttributeList::get(Ctx, AttributeList::FunctionIndex, FnAttrs);

  return M->getOrInsertFunction("resolve_get_base_and_limit",
                                FunctionType::get(struct_ty, {ptr_ty}, false),
                                attrs);
}

static Function *getOrCreateResolveAccessOk(Module *M) {
  Twine handlerName = "resolve_access_ok";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto bool_ty = Type::getIntNTy(Ctx, 1);

  FunctionType *resolveAccessOkFnTy =
      FunctionType::get(bool_ty, {ptr_ty, size_ty}, false);

  Function *resolveAccessOkFn = Function::Create(
      resolveAccessOkFnTy, Function::InternalLinkage, handlerName, M);

  // Adding an attribute to always inline this function
  resolveAccessOkFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolveAccessOkFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "", resolveAccessOkFn);
  BasicBlock *TrueBB = BasicBlock::Create(Ctx, "", resolveAccessOkFn);
  BasicBlock *FalseBB = BasicBlock::Create(Ctx, "", resolveAccessOkFn);

  builder.SetInsertPoint(EntryBB);

  Value *basePtr = resolveAccessOkFn->getArg(0);
  Value *accessSize = resolveAccessOkFn->getArg(1);

  Value *baseAndLimit =
      builder.CreateCall(getResolveBaseAndLimit(M), {basePtr});
  Value *limitValue = builder.CreateExtractValue(baseAndLimit, 1);
  Value *limitInt = builder.CreatePtrToInt(limitValue, size_ty);
  Value *baseInt = builder.CreatePtrToInt(basePtr, size_ty);
  Value *isZero = builder.CreateICmpEQ(limitInt, ConstantInt::get(size_ty, 0));
  builder.CreateCondBr(isZero, TrueBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *accessLimit = builder.CreateAdd(
      baseInt, builder.CreateSub(accessSize, ConstantInt::get(size_ty, 1)));

  Value *withinBounds = builder.CreateICmpULE(accessLimit, limitInt);

  builder.CreateCondBr(withinBounds, TrueBB, FalseBB);

  builder.SetInsertPoint(TrueBB);
  builder.CreateRet(ConstantInt::getTrue(Ctx));

  builder.SetInsertPoint(FalseBB);
  builder.CreateRet(ConstantInt::getFalse(Ctx));

  raw_ostream &out = errs();
  out << *resolveAccessOkFn;
  if (verifyFunction(*resolveAccessOkFn, &out)) {
  }

  return resolveAccessOkFn;
}

static Function *getOrCreateBoundsCheckLoadSanitizer(
    Module *M, LLVMContext &Ctx, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_ld_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName)) {
    return handler;
  }

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);

  FunctionType *sanitizeLoadFnTy = FunctionType::get(ty, {ptr_ty}, false);

  Function *sanitizeLoadFn = Function::Create(
      sanitizeLoadFnTy, Function::InternalLinkage, handlerName, M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);
  BasicBlock *NormalLoadBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);
  BasicBlock *SanitizeLoadBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);

  Value *basePtr = sanitizeLoadFn->getArg(0);

  builder.SetInsertPoint(EntryBB);
  Value *withinBounds = builder.CreateCall(
      getOrCreateResolveAccessOk(M), {basePtr, ConstantExpr::getSizeOf(ty)});

  builder.CreateCondBr(withinBounds, NormalLoadBB, SanitizeLoadBB);

  // NormalLoadBB: Return the loaded value.
  builder.SetInsertPoint(NormalLoadBB);
  LoadInst *load = builder.CreateLoad(ty, basePtr);
  builder.CreateRet(load);

  // SanitizeLoadBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeLoadBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateRet(Constant::getNullValue(ty));

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeLoadFn;
  if (verifyFunction(*sanitizeLoadFn, &out)) {
  }

  return sanitizeLoadFn;
}

static Function *getOrCreateBoundsCheckStoreSanitizer(
    Module *M, LLVMContext &Ctx, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_st_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName)) {
    return handler;
  }

  IRBuilder<> builder(Ctx);

  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);

  FunctionType *sanitizeStoreFnTy =
      FunctionType::get(void_ty, {ptr_ty, ty}, false);

  Function *sanitizeStoreFn = Function::Create(
      sanitizeStoreFnTy, Function::InternalLinkage, handlerName, M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);
  BasicBlock *NormalStoreBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);
  BasicBlock *SanitizeStoreBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);

  Value *basePtr = sanitizeStoreFn->getArg(0);
  Value *storedVal = sanitizeStoreFn->getArg(1);
  builder.SetInsertPoint(EntryBB);

  Value *withinBounds = builder.CreateCall(
      getOrCreateResolveAccessOk(M), {basePtr, ConstantExpr::getSizeOf(ty)});

  builder.CreateCondBr(withinBounds, NormalStoreBB, SanitizeStoreBB);

  // NormalStoreBB: Store value @ addr
  builder.SetInsertPoint(NormalStoreBB);
  builder.CreateStore(storedVal, basePtr);
  builder.CreateRetVoid();

  // SanitizeStoreBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeStoreBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateRetVoid();

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeStoreFn;
  if (verifyFunction(*sanitizeStoreFn, &out)) {
  }

  return sanitizeStoreFn;
}

static Function *getOrCreateBoundsCheckMemcpySanitizer(
    Module *M, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_memcpy";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *sanitizeMemcpyFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false);

  Function *sanitizeMemcpyFn = Function::Create(
      sanitizeMemcpyFnTy, Function::InternalLinkage, handlerName, M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);
  BasicBlock *SanitizeMemcpyBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);

  // EntryBB: Call resolve_access_ok
  // to verify correct bounds of allocation
  builder.SetInsertPoint(EntryBB);

  // Extract dst, src, size arguments from function
  Value *dst_ptr = sanitizeMemcpyFn->getArg(0);
  Value *src_ptr = sanitizeMemcpyFn->getArg(1);
  Value *size_arg = sanitizeMemcpyFn->getArg(2);

  Value *check_src_bd =
      builder.CreateCall(getOrCreateResolveAccessOk(M), {src_ptr, size_arg});
  Value *check_dst_bd =
      builder.CreateCall(getOrCreateResolveAccessOk(M), {dst_ptr, size_arg});

  Value *withinBounds = builder.CreateAnd(check_src_bd, check_dst_bd);
  builder.CreateCondBr(withinBounds, NormalBB, SanitizeMemcpyBB);

  // NormalBB: Call memcpy and return the ptr
  builder.SetInsertPoint(NormalBB);
  FunctionCallee memcpyFn = M->getOrInsertFunction(
      "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memcpyPtr = builder.CreateCall(memcpyFn, {dst_ptr, src_ptr, size_arg});
  builder.CreateRet(memcpyPtr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemcpyBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateRet(dst_ptr);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeMemcpyFn;
  if (verifyFunction(*sanitizeMemcpyFn, &out)) {
  }
  return sanitizeMemcpyFn;
}

static Function *getOrCreateBoundsCheckMemsetSanitizer(
    Module *M, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_memset";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i32_ty = Type::getInt32Ty(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *sanitizeMemsetFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, i32_ty, size_ty}, false);

  Function *sanitizeMemsetFn = Function::Create(
      sanitizeMemsetFnTy, Function::InternalLinkage, handlerName, M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeMemsetFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "", sanitizeMemsetFn);
  BasicBlock *SanitizeMemsetBB = BasicBlock::Create(Ctx, "", sanitizeMemsetFn);

  builder.SetInsertPoint(EntryBB);

  // Extract arguments for memset
  Value *basePtr = sanitizeMemsetFn->getArg(0);
  Value *valueArg = sanitizeMemsetFn->getArg(1);
  Value *accessSize = sanitizeMemsetFn->getArg(2);

  Value *check_dst_bd =
      builder.CreateCall(getOrCreateResolveAccessOk(M), {basePtr, accessSize});
  builder.CreateCondBr(check_dst_bd, NormalBB, SanitizeMemsetBB);

  // NormalBB: call memset and return the pointer
  builder.SetInsertPoint(NormalBB);

  FunctionCallee memsetFn = M->getOrInsertFunction(
      "memset", FunctionType::get(ptr_ty, {ptr_ty, i32_ty, size_ty}, false));

  Value *memsetPtr =
      builder.CreateCall(memsetFn, {basePtr, valueArg, accessSize});
  builder.CreateRet(memsetPtr);

  // SanitizeMemsetBB: Jump to remediation
  builder.SetInsertPoint(SanitizeMemsetBB);
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateRet(basePtr);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeMemsetFn;
  if (verifyFunction(*sanitizeMemsetFn, &out)) {
  }
  return sanitizeMemsetFn;
}

static Function *getOrCreateResolveGep(Module *M) {
  Twine handlerName = "resolve_gep";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveGepFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty}, false);

  Function *resolveGepFn = Function::Create(
      resolveGepFnTy, Function::InternalLinkage, handlerName, M);

  // Adding attribute to always inline
  resolveGepFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolveGepFn);
  BasicBlock *CheckComputedPtrBB = BasicBlock::Create(Ctx, "", resolveGepFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "", resolveGepFn);
  BasicBlock *OnePastBB = BasicBlock::Create(Ctx, "", resolveGepFn);

  // EntryBB: Call libresolve get_base_and_limit
  // to retrieve the last valid byte address of obj
  builder.SetInsertPoint(EntryBB);

  // Extract the base and derived pointer
  Value *basePtr = resolveGepFn->getArg(0);
  Value *derivedPtr = resolveGepFn->getArg(1);

  Value *baseAndLimit =
      builder.CreateCall(getResolveBaseAndLimit(M), {basePtr});
  Value *baseValue = builder.CreateExtractValue(baseAndLimit, 0);
  Value *limitValue = builder.CreateExtractValue(baseAndLimit, 1);

  Value *baseInt = builder.CreatePtrToInt(baseValue, size_ty);
  Value *limitInt = builder.CreatePtrToInt(limitValue, size_ty);
  Value *isSentinel =
      builder.CreateICmpEQ(limitInt, ConstantInt::get(size_ty, 0));
  builder.CreateCondBr(isSentinel, NormalBB, CheckComputedPtrBB);

  builder.SetInsertPoint(CheckComputedPtrBB);
  Value *derivedInt = builder.CreatePtrToInt(derivedPtr, size_ty);
  Value *underLimit = builder.CreateICmpULE(derivedInt, limitInt);
  Value *aboveBase = builder.CreateICmpUGE(derivedInt, baseInt);
  Value *withinBounds = builder.CreateAnd(underLimit, aboveBase);

  builder.CreateCondBr(withinBounds, NormalBB, OnePastBB);

  builder.SetInsertPoint(NormalBB);
  builder.CreateRet(derivedPtr);

  builder.SetInsertPoint(OnePastBB);

  // Return a pointer that is clamped at one past the last valid byte address
  Value *onePastInt = builder.CreateAdd(limitInt, ConstantInt::get(size_ty, 1));
  Value *onePastPtr = builder.CreateIntToPtr(onePastInt, ptr_ty);
  builder.CreateRet(onePastPtr);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *resolveGepFn;
  if (verifyFunction(*resolveGepFn, &out)) {
  }
  return resolveGepFn;
}

static FunctionCallee getResolveMalloc(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction("resolve_malloc",
                                FunctionType::get(ptr_ty, {size_ty}, false));
}

static FunctionCallee getResolveRealloc(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
      "resolve_realloc", FunctionType::get(ptr_ty, {ptr_ty, size_ty}, false));
}

static FunctionCallee getResolveCalloc(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
      "resolve_calloc", FunctionType::get(ptr_ty, {size_ty, size_ty}, false));
}

static FunctionCallee getResolveStackObj(Module *M) {
  auto &Ctx = M->getContext();
  auto void_ty = Type::getVoidTy(Ctx);
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
      "resolve_stack_obj",
      FunctionType::get(void_ty, {ptr_ty, size_ty}, false));
}

static FunctionCallee getResolveFree(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);

  return M->getOrInsertFunction("resolve_free",
                                FunctionType::get(void_ty, {ptr_ty}, false));
}

static FunctionCallee getResolveStrdup(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);

  return M->getOrInsertFunction("resolve_strdup",
                                FunctionType::get(ptr_ty, {ptr_ty}, false));
}

static FunctionCallee getResolveStrndup(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
      "resolve_strndup", FunctionType::get(ptr_ty, {ptr_ty, size_ty}, false));
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

  auto invalidateFn = M->getOrInsertFunction(
      "resolve_invalidate_stack", FunctionType::get(void_ty, {ptr_ty}, false));

  auto handle_alloca = [&](auto *allocaInst) {
    bool hasStart = false;
    bool hasEnd = false;

    Type *allocatedType = allocaInst->getAllocatedType();
    uint64_t typeSize = DL.getTypeAllocSize(allocatedType);

    // Create padded alloca type
    builder.SetInsertPoint(allocaInst->getNextNode());
    StructType *paddedType = StructType::get(allocatedType, Type::getInt8Ty(Ctx));
    AllocaInst *paddedAlloca = builder.CreateAlloca(paddedType, nullptr, allocaInst->getName() + ".pad"); 
    paddedAlloca->setAlignment(allocaInst->getAlign());

    // Emit a gep instruction to point to allocated type 
    Value *typedPtr = builder.CreateStructGEP(paddedType, paddedAlloca, 0);
    // NOTE: attaching metadata to gep instruction to prevent instrumentation of gep
    if (auto *inst = dyn_cast<Instruction>(typedPtr)) {
      inst->setMetadata("resolve.noinstrument", MDNode::get(Ctx, {}));
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
      if (auto* intrinsic = dyn_cast<IntrinsicInst>(call)) {
        if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_start) {
          builder.SetInsertPoint(call->getNextNode());
          builder.CreateCall(getResolveStackObj(M), { typedPtr, ConstantInt::get(size_ty, typeSize )});
          call->setOperand(1, typedPtr);
        }

        if (intrinsic->getIntrinsicID() == Intrinsic::lifetime_end) {
          builder.SetInsertPoint(call->getNextNode());
          builder.CreateCall(invalidateFn, { typedPtr });
          call->setOperand(1, typedPtr);
        }
      }
    }

    allocaInst->replaceAllUsesWith(paddedAlloca);

    // Instrument allocas that don't have lifetime markers
    // Not all llvm-ir produced hasStart == hasEnd
    if (!hasStart) {
      if (auto *inst = dyn_cast<Instruction>(typedPtr)) {
        builder.SetInsertPoint(inst->getNextNode());
        builder.CreateCall(getResolveStackObj(M),
        { typedPtr, ConstantInt::get(size_ty, typeSize )});
      }
    }

    if (!hasEnd) { toFreeList.push_back(paddedAlloca); }
    allocaInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
        allocas.push_back(inst);
      }
    }
  }

  for (auto *alloca : allocas) {
    handle_alloca(alloca);
  }

  // Find low and high allocations and pass to resolve_invaliate_stack
  if (toFreeList.empty()) {
    return;
  }

  // Stack grows down, so first allocation is high, last is low
  // Hmm.. compiler seems to be reordering the allocas in ways
  // that break this assumption
  // auto low = allocaList.back();
  // auto high = allocaList.front();
  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *inst = dyn_cast<ReturnInst>(&instr)) {
        builder.SetInsertPoint(inst);
        for (auto *padded : toFreeList) {
          builder.CreateCall(invalidateFn, { padded });
        }
      }
    }
  }
}

void instrumentMalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> mallocList;

  auto handle_malloc = [&](auto *mallocInst) {
    builder.SetInsertPoint(mallocInst);
    Value *sizeArg = mallocInst->getArgOperand(0);
    CallInst *resolveMallocInst = 
        builder.CreateCall(getResolveMalloc(M), { sizeArg });
    mallocInst->replaceAllUsesWith(resolveMallocInst);
    mallocInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();

        if (fnName == "malloc") {
          mallocList.push_back(call);
        }
      }
    }
  }

  for (auto malloc : mallocList) {
    handle_malloc(malloc);
  }
}

void instrumentRealloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> reallocList;

  auto handle_realloc = [&](auto *reallocInst) {
    builder.SetInsertPoint(reallocInst);
    Value *ptrArg = reallocInst->getArgOperand(0);
    Value *sizeArg = reallocInst->getArgOperand(1);
    CallInst *resolveReallocCall =
      builder.CreateCall(getResolveRealloc(M), {ptrArg, sizeArg});
    reallocInst->replaceAllUsesWith(resolveReallocCall);
    reallocInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();

        if (fnName == "realloc") {
          reallocList.push_back(call);
        }
      }
    }
  }

  for (auto realloc : reallocList) {
    handle_realloc(realloc);
  }
}

void instrumentCalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> callocList;

  auto handle_calloc = [&](auto *callocInst) {
    builder.SetInsertPoint(callocInst);
    Value *numArg = callocInst->getArgOperand(0);
    Value *sizeArg = callocInst->getArgOperand(1);
    CallInst *resolveCallocCall =
        builder.CreateCall(getResolveCalloc(M), {numArg, sizeArg});
    callocInst->replaceAllUsesWith(resolveCallocCall);
    callocInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();
        if (fnName == "calloc") {
          callocList.push_back(call);
        }
      }
    }
  }

  for (auto calloc : callocList) {
    handle_calloc(calloc);
  }
}

void instrumentFree(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> freeList;

  auto handle_free = [&](auto *freeInst) {
    builder.SetInsertPoint(freeInst);
    Value *ptrArg = freeInst->getArgOperand(0);
    CallInst *resolveFreeCall = builder.CreateCall(getResolveFree(M), {ptrArg});
    freeInst->replaceAllUsesWith(resolveFreeCall);
    freeInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();
        if (fnName == "free") {
          freeList.push_back(call);
        }
      }
    }
  }

  for (auto free : freeList) {
    handle_free(free);
  }
}

void instrumentStrdup(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> strdupList;

  auto handle_strdup = [&](auto *strdupInst) {
    builder.SetInsertPoint(strdupInst);
    Value *ptrArg = strdupInst->getArgOperand(0);
    CallInst *resolveStrdupCall =
        builder.CreateCall(getResolveStrdup(M), {ptrArg});
    strdupInst->replaceAllUsesWith(resolveStrdupCall);
    strdupInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();
        if (fnName == "strdup") {
          strdupList.push_back(call);
        }
      }
    }
  }

  for (auto strdup : strdupList) {
    handle_strdup(strdup);
  }
}

void instrumentStrndup(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> strndupList;

  auto handle_strndup = [&](auto *strndupInst) {
    builder.SetInsertPoint(strndupInst);
    Value *ptrArg = strndupInst->getArgOperand(0);
    Value *sizeArg = strndupInst->getArgOperand(1);
    CallInst *resolveStrndupCall =
        builder.CreateCall(getResolveStrndup(M), {ptrArg, sizeArg});
    strndupInst->replaceAllUsesWith(resolveStrndupCall);
    strndupInst->eraseFromParent();
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) {
          continue;
        }

        StringRef fnName = calledFn->getName();
        if (fnName == "strndup") {
          strndupList.push_back(call);
        }
      }
    }
  }

  for (auto strndup : strndupList) {
    handle_strndup(strndup);
  }
}

void instrumentGEP(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();
  std::vector<GetElementPtrInst *> gepList;
  std::unordered_set<GetElementPtrInst *> visitedGep;

  auto handle_gep = [&](auto *gep) {
    if (visitedGep.contains(gep)) {
      return;
    }

    if (gep->getMetadata("resolve.noinstrument")) { return; }

    Value *basePtr = gep->getPointerOperand();
    GetElementPtrInst *derivedPtr = gep;
    gep->setIsInBounds(false);

    // If we are chaining geps we do not need to check each individually,
    // only the total range
    while (derivedPtr->hasOneUser()) {
      if (auto *gep2 = dyn_cast<GetElementPtrInst>(derivedPtr->user_back())) {
        gep2->setIsInBounds(false);
        visitedGep.insert(gep2);
        derivedPtr = gep2;
      } else {
        break;
      }
    }

    SmallVector<User *, 8> gep_users;
    for (User *U : derivedPtr->users()) {
      gep_users.push_back(U);
    }

    builder.SetInsertPoint(derivedPtr->getNextNode());
    auto resolveGepCall =
        builder.CreateCall(getOrCreateResolveGep(M), {basePtr, derivedPtr});

    // Iterate over all the users of the gep instruction and
    // replace their operands with resolve_gep result
    for (User *U : gep_users) {
      if (U != resolveGepCall) {
        U->replaceUsesOfWith(derivedPtr, resolveGepCall);
      }
    }

    visitedGep.insert(gep);
  };

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *gep = dyn_cast<GetElementPtrInst>(&inst)) {
        handle_gep(gep);
      }
    }
  }
}

void sanitizeMemcpy(Function *F,
                    Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<Instruction *> memcpyList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (isa<MemCpyInst>(&inst)) {
        memcpyList.push_back(&inst);
        continue;
      }

      auto *call = dyn_cast<CallInst>(&inst);
      if (!call) {
        continue;
      }

      Function *calledFn = call->getCalledFunction();
      if (!calledFn) {
        continue;
      }

      StringRef fnName = calledFn->getName();

      if (fnName == "memcpy") {
        memcpyList.push_back(call);
      }
    }
  }

  for (auto Inst : memcpyList) {
    builder.SetInsertPoint(Inst);

    Value *dstPtr = nullptr;
    Value *srcPtr = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemCpyInst>(Inst)) {
      dstPtr = MI->getDest();
      srcPtr = MI->getSource();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(Inst)) {
      dstPtr = MC->getArgOperand(0);
      srcPtr = MC->getArgOperand(1);
      sizeArg = MC->getArgOperand(2);
    }

    auto memcpyFn =
        getOrCreateBoundsCheckMemcpySanitizer(F->getParent(), strategy);
    auto memcpyCall = builder.CreateCall(memcpyFn, {dstPtr, srcPtr, sizeArg});
    Inst->replaceAllUsesWith(memcpyCall);
    Inst->eraseFromParent();
  }
}

void sanitizeMemset(Function *F,
                    Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<Instruction *> memsetList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (isa<MemSetInst>(&inst)) {
        memsetList.push_back(&inst);
        continue;
      }

      auto *call = dyn_cast<CallInst>(&inst);
      if (!call) {
        continue;
      }

      Function *calledFn = call->getCalledFunction();
      if (!calledFn) {
        continue;
      }

      StringRef fnName = calledFn->getName();

      if (fnName == "memset") {
        memsetList.push_back(call);
      }
    }
  }

  for (auto Inst : memsetList) {
    builder.SetInsertPoint(Inst);

    Value *basePtr = nullptr;
    Value *valueArg = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemSetInst>(Inst)) {
      basePtr = MI->getDest();
      valueArg = MI->getValue();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(Inst)) {
      basePtr = MC->getArgOperand(0);
      valueArg = MC->getArgOperand(1);
      sizeArg = MC->getArgOperand(2);
    }

    // Normalize value parameter type
    Type *ExpectedValueTy = Type::getInt32Ty(Ctx);
    if (valueArg->getType() != ExpectedValueTy) {
      valueArg = builder.CreateIntCast(valueArg, ExpectedValueTy, false);
    }

    // Normalize length parameter type
    Type *ExpectedLengthTy = Type::getInt64Ty(Ctx);
    if (sizeArg->getType() != ExpectedLengthTy) {
      sizeArg = builder.CreateIntCast(sizeArg, ExpectedLengthTy, false);
    }

    auto memsetFn =
        getOrCreateBoundsCheckMemsetSanitizer(F->getParent(), strategy);
    auto memsetCall =
        builder.CreateCall(memsetFn, {basePtr, valueArg, sizeArg});
    Inst->replaceAllUsesWith(memsetCall);
    Inst->eraseFromParent();
  }
}

void sanitizeLoadStore(Function *F,
                       Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<LoadInst *> loadList;
  std::vector<StoreInst *> storeList;

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE:
  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
    break;

  default:
    llvm::errs() << "[CVEAssert] Error: sanitizeLoadStore does not support "
                    "remediation strategy "
                 << "defaulting to continue strategy!\n";
    strategy = Vulnerability::RemediationStrategies::CONTINUE;
    break;
  }

  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (auto *load = dyn_cast<LoadInst>(&I)) {
        loadList.push_back(load);
      } else if (auto *store = dyn_cast<StoreInst>(&I)) {
        storeList.push_back(store);
      }
    }
  }

  for (auto Inst : loadList) {
    builder.SetInsertPoint(Inst);
    auto ptr = Inst->getPointerOperand();
    auto valueTy = Inst->getType();

    // Skip trivially correct accesses to stack values in this function (i.e.,
    // most automatic variables) Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueTy)
        continue;
    }

    auto loadFn = getOrCreateBoundsCheckLoadSanitizer(
        F->getParent(), F->getContext(), valueTy, strategy);

    auto sanitizedLoad = builder.CreateCall(loadFn, {ptr});
    Inst->replaceAllUsesWith(sanitizedLoad);
    Inst->removeFromParent();
    Inst->deleteValue();
  }

  for (auto Inst : storeList) {
    builder.SetInsertPoint(Inst);
    auto ptr = Inst->getPointerOperand();
    auto valueTy = Inst->getValueOperand()->getType();

    // Skip trivially correct accesses to stack values in this function (i.e.,
    // most automatic variables) Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueTy)
        continue;
    }

    auto storeFn = getOrCreateBoundsCheckStoreSanitizer(
        F->getParent(), F->getContext(), valueTy, strategy);

    auto sanitizedStore =
        builder.CreateCall(storeFn, {ptr, Inst->getValueOperand()});
    Inst->replaceAllUsesWith(sanitizedStore);
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeMemInstBounds(Function *F,
                           Vulnerability::RemediationStrategies strategy) {
  instrumentGEP(F);
  sanitizeMemcpy(F, strategy);
  sanitizeMemset(F, strategy);
  sanitizeLoadStore(F, strategy);
}