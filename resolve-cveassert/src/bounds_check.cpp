/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/raw_ostream.h"

#include "CVEAssert.hpp"
#include "Vulnerability.hpp"
#include "helpers.hpp"

#include <map>
#include <unordered_set>

using namespace llvm;

/// Static classification of a pointer's underlying allocation.
/// Used for resolving stack/heap specific sobj lookups when
/// getUnderlyingObject (classifyPointer) provides a definitive answer.
enum class BoundsClass { Stack, Heap, Generic };

static const char *classTag(BoundsClass cls) {
  switch (cls) {
  case BoundsClass::Stack:
    return "stack";
  case BoundsClass::Heap:
    return "heap";
  default:
    return "generic";
  }
}

/// Walks the pointer's def chain (through GEPs/casts) to its underlying object
/// and classifies it.
static BoundsClass classifyPointer(const Value *ptr) {
  const Value *obj = getUnderlyingObject(ptr);

  if (isa<AllocaInst>(obj)) {
    return BoundsClass::Stack;
  }

  if (auto *call = dyn_cast<CallInst>(obj)) {
    if (Function *callee = call->getCalledFunction()) {
      StringRef n = callee->getName();
      if (n == "malloc" || n == "calloc" || n == "realloc" || n == "strdup" ||
          n == "strndup" || n == "__resolve_malloc" ||
          n == "__resolve_calloc" || n == "__resolve_realloc" ||
          n == "__resolve_strdup" || n == "__resolve_strndup") {
        return BoundsClass::Heap;
      }
    }
  }

  return BoundsClass::Generic;
}

static FunctionCallee getOrCreateResolveGetBounds(Module *M, BoundsClass cls) {
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

  const char *name;
  switch (cls) {
  case BoundsClass::Stack:
    name = "__resolve_get_bounds_stack";
    break;
  case BoundsClass::Heap:
    name = "__resolve_get_bounds_heap";
    break;
  default:
    name = "__resolve_get_bounds";
    break;
  }

  return M->getOrInsertFunction(
      name, FunctionType::get(struct_ty, {ptr_ty}, false), attrs);
}

static Function *getOrCreateAccessOk(Module *M, BoundsClass cls) {
  std::string handlerName = std::string("__cve_access_ok_") + classTag(cls);
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto bool_ty = Type::getIntNTy(Ctx, 1);

  FunctionType *resolveAccessOkFnTy =
      FunctionType::get(bool_ty, {ptr_ty, size_ty}, false);

  Function *resolveAccessOkFn =
      getOrCreateResolveHelper(M, handlerName, resolveAccessOkFnTy);

  if (!resolveAccessOkFn->empty()) {
    recordPatchFunction(resolveAccessOkFn);
    return resolveAccessOkFn;
  }

  // Adding an attribute to always inline this function
  resolveAccessOkFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveAccessOkFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveAccessOkFn);
  BasicBlock *TrueBB =
      BasicBlock::Create(Ctx, "safe.access", resolveAccessOkFn);
  BasicBlock *FalseBB =
      BasicBlock::Create(Ctx, "unsafe.access", resolveAccessOkFn);

  builder.SetInsertPoint(EntryBB);

  Value *basePtr = resolveAccessOkFn->getArg(0);
  Value *accessSize = resolveAccessOkFn->getArg(1);

  Value *baseAndLimit = builder.CreateCall(getOrCreateResolveGetBounds(M, cls),
                                           {basePtr}, "resolve.bounds");
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

  validateIR(resolveAccessOkFn);
  recordPatchFunction(resolveAccessOkFn);
  return resolveAccessOkFn;
}

static Function *getOrCreateBoundsCheckLoadSanitizer(
    Function *F, Type *ty, Vulnerability::RemediationStrategies strategy,
    BoundsClass cls) {
  std::string handlerName =
      "__cve_bound_ld_" + getLLVMType(ty) + "_" + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i1_ty = Type::getInt1Ty(Ctx);
  auto usize_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveLoadFnTy = FunctionType::get(ty, {ptr_ty}, false);
  Function *resolveLoadFn =
      getOrCreateResolveHelper(M, handlerName, resolveLoadFnTy);

  if (!resolveLoadFn->empty()) {
    recordPatchFunction(resolveLoadFn);
    return resolveLoadFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveLoadFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveLoadFn);
  BasicBlock *NormalLoadBB =
      BasicBlock::Create(Ctx, "safe.load", resolveLoadFn);
  BasicBlock *SanitizeLoadBB =
      BasicBlock::Create(Ctx, "sanitize.load", resolveLoadFn);

  builder.SetInsertPoint(EntryBB);
  Value *basePtr = resolveLoadFn->getArg(0);
  createSanitizerGateBranch(builder, F, 0, NormalLoadBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *withinBounds = builder.CreateCall(
      getOrCreateAccessOk(M, cls), {basePtr, ConstantExpr::getSizeOf(ty)});

  builder.CreateCondBr(withinBounds, NormalLoadBB, SanitizeLoadBB);

  // NormalLoadBB: Return the loaded value.
  builder.SetInsertPoint(NormalLoadBB);
  LoadInst *load = builder.CreateLoad(ty, basePtr);
  builder.CreateRet(load);

  // SanitizeLoadBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeLoadBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(Constant::getNullValue(ty));
  }

  validateIR(resolveLoadFn);
  recordPatchFunction(resolveLoadFn);
  return resolveLoadFn;
}

static Function *getOrCreateBoundsCheckStoreSanitizer(
    Function *F, Type *ty, Vulnerability::RemediationStrategies strategy,
    BoundsClass cls) {
  std::string handlerName =
      "__cve_bound_st_" + getLLVMType(ty) + "_" + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);
  auto usize_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveStoreFnTy =
      FunctionType::get(void_ty, {ptr_ty, ty}, false);

  Function *resolveStoreFn =
      getOrCreateResolveHelper(M, handlerName, resolveStoreFnTy);
  if (!resolveStoreFn->empty()) {
    recordPatchFunction(resolveStoreFn);
    return resolveStoreFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveStoreFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveStoreFn);
  BasicBlock *NormalStoreBB =
      BasicBlock::Create(Ctx, "safe.store", resolveStoreFn);
  BasicBlock *SanitizeStoreBB =
      BasicBlock::Create(Ctx, "sanitize.store", resolveStoreFn);

  builder.SetInsertPoint(EntryBB);
  Value *basePtr = resolveStoreFn->getArg(0);
  Value *storedVal = resolveStoreFn->getArg(1);

  createSanitizerGateBranch(builder, F, 0, NormalStoreBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *withinBounds = builder.CreateCall(
      getOrCreateAccessOk(M, cls), {basePtr, ConstantExpr::getSizeOf(ty)});

  builder.CreateCondBr(withinBounds, NormalStoreBB, SanitizeStoreBB);

  builder.SetInsertPoint(NormalStoreBB);
  builder.CreateStore(storedVal, basePtr);
  builder.CreateRetVoid();

  // SanitizeStoreBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeStoreBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRetVoid();
  }

  validateIR(resolveStoreFn);
  recordPatchFunction(resolveStoreFn);
  return resolveStoreFn;
}

static Function *getOrCreateBoundsCheckMemcpySanitizer(
    Function *F, Vulnerability::RemediationStrategies strategy,
    BoundsClass srcCls, BoundsClass dstCls) {
  std::string handlerName =
      std::string("__cve_memcpy_") + classTag(srcCls) + "_" + classTag(dstCls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveMemmoveFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false);

  Function *resolveMemmoveFn =
      getOrCreateResolveHelper(M, handlerName, resolveMemmoveFnTy);
  if (!resolveMemmoveFn->empty()) {
    recordPatchFunction(resolveMemmoveFn);
    return resolveMemmoveFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveMemmoveFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveMemmoveFn);
  BasicBlock *NormalBB =
      BasicBlock::Create(Ctx, "safe.memcpy", resolveMemmoveFn);
  BasicBlock *SanitizeMemcpyBB =
      BasicBlock::Create(Ctx, "sanitize.memcpy", resolveMemmoveFn);

  builder.SetInsertPoint(EntryBB);
  // Extract dst, src, size arguments from function
  Value *dstPtr = resolveMemmoveFn->getArg(0);
  Value *srcPtr = resolveMemmoveFn->getArg(1);
  Value *sizeArg = resolveMemmoveFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, NormalBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *check_src_access =
      builder.CreateCall(getOrCreateAccessOk(M, srcCls), {srcPtr, sizeArg});
  Value *check_dst_access =
      builder.CreateCall(getOrCreateAccessOk(M, dstCls), {dstPtr, sizeArg});

  Value *withinBounds = builder.CreateAnd(check_src_access, check_dst_access);
  builder.CreateCondBr(withinBounds, NormalBB, SanitizeMemcpyBB);

  // NormalBB: Call memcpy and return the ptr
  builder.SetInsertPoint(NormalBB);
  FunctionCallee memcpyFn = M->getOrInsertFunction(
      "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memcpyPtr = builder.CreateCall(memcpyFn, {dstPtr, srcPtr, sizeArg});
  builder.CreateRet(memcpyPtr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemcpyBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(dstPtr);
  }
  validateIR(resolveMemmoveFn);
  recordPatchFunction(resolveMemmoveFn);
  return resolveMemmoveFn;
}

static Function *getOrCreateBoundsCheckMemmoveSanitizer(
    Function *F, Vulnerability::RemediationStrategies strategy,
    BoundsClass srcCls, BoundsClass dstCls) {
  std::string handlerName =
      std::string("__cve_memmove_") + classTag(srcCls) + "_" + classTag(dstCls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveMemmoveFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false);

  Function *resolveMemmoveFn =
      getOrCreateResolveHelper(M, handlerName, resolveMemmoveFnTy);
  if (!resolveMemmoveFn->empty()) {
    recordPatchFunction(resolveMemmoveFn);
    return resolveMemmoveFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveMemmoveFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveMemmoveFn);
  BasicBlock *NormalBB =
      BasicBlock::Create(Ctx, "safe.memmove", resolveMemmoveFn);
  BasicBlock *SanitizeMemmoveBB =
      BasicBlock::Create(Ctx, "sanitize.memmove", resolveMemmoveFn);

  builder.SetInsertPoint(EntryBB);
  // Extract dst, src, size arguments from function
  Value *dstPtr = resolveMemmoveFn->getArg(0);
  Value *srcPtr = resolveMemmoveFn->getArg(1);
  Value *sizeArg = resolveMemmoveFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, NormalBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *check_src_access =
      builder.CreateCall(getOrCreateAccessOk(M, srcCls), {srcPtr, sizeArg});
  Value *check_dst_access =
      builder.CreateCall(getOrCreateAccessOk(M, dstCls), {dstPtr, sizeArg});

  Value *withinBounds = builder.CreateAnd(check_src_access, check_dst_access);
  builder.CreateCondBr(withinBounds, NormalBB, SanitizeMemmoveBB);

  // NormalBB: Call memcpy and return the ptr
  builder.SetInsertPoint(NormalBB);
  FunctionCallee memmoveFn = M->getOrInsertFunction(
      "memmove", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memmovePtr = builder.CreateCall(memmoveFn, {dstPtr, srcPtr, sizeArg});
  builder.CreateRet(memmovePtr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemmoveBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(dstPtr);
  }

  validateIR(resolveMemmoveFn);
  recordPatchFunction(resolveMemmoveFn);
  return resolveMemmoveFn;
}

static Function *getOrCreateBoundsCheckMemsetSanitizer(
    Function *F, Vulnerability::RemediationStrategies strategy,
    BoundsClass cls) {
  std::string handlerName = std::string("__cve_memset_") + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i32_ty = Type::getInt32Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveMemsetFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, i32_ty, size_ty}, false);

  Function *resolveMemsetFn =
      getOrCreateResolveHelper(M, handlerName, resolveMemsetFnTy);
  if (!resolveMemsetFn->empty()) {
    recordPatchFunction(resolveMemsetFn);
    return resolveMemsetFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveMemsetFn);
  BasicBlock *CheckAccessBB =
      BasicBlock::Create(Ctx, "check.access", resolveMemsetFn);
  BasicBlock *NormalBB =
      BasicBlock::Create(Ctx, "safe.memset", resolveMemsetFn);
  BasicBlock *SanitizeMemsetBB =
      BasicBlock::Create(Ctx, "sanitize.memset", resolveMemsetFn);

  builder.SetInsertPoint(EntryBB);
  // Extract arguments for memset
  Value *basePtr = resolveMemsetFn->getArg(0);
  Value *valueArg = resolveMemsetFn->getArg(1);
  Value *accessSize = resolveMemsetFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, NormalBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *check_dst_access =
      builder.CreateCall(getOrCreateAccessOk(M, cls), {basePtr, accessSize});
  builder.CreateCondBr(check_dst_access, NormalBB, SanitizeMemsetBB);

  // NormalBB: call memset and return the pointer
  builder.SetInsertPoint(NormalBB);

  FunctionCallee memsetFn = M->getOrInsertFunction(
      "memset", FunctionType::get(ptr_ty, {ptr_ty, i32_ty, size_ty}, false));

  Value *memsetPtr =
      builder.CreateCall(memsetFn, {basePtr, valueArg, accessSize});
  builder.CreateRet(memsetPtr);

  builder.SetInsertPoint(SanitizeMemsetBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(basePtr);
  }

  validateIR(resolveMemsetFn);
  recordPatchFunction(resolveMemsetFn);
  return resolveMemsetFn;
}

static Function *getOrCreateResolveGep(Function *F, BoundsClass cls) {
  std::string handlerName = std::string("__cve_gep_") + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveGepFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty}, false);

  Function *resolveGepFn =
      getOrCreateResolveHelper(M, handlerName, resolveGepFnTy);
  if (!resolveGepFn->empty()) {
    recordPatchFunction(resolveGepFn);
    return resolveGepFn;
  }

  // Adding attribute to always inline
  resolveGepFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveGepFn);
  BasicBlock *GetBaseAndLimitBB =
      BasicBlock::Create(Ctx, "get.bounds", resolveGepFn);
  BasicBlock *CheckComputedPtrBB =
      BasicBlock::Create(Ctx, "check.access", resolveGepFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "safe.ptr", resolveGepFn);
  BasicBlock *OnePastBB = BasicBlock::Create(Ctx, "tainted.ptr", resolveGepFn);

  builder.SetInsertPoint(EntryBB);
  // Extract the base and derived pointer
  Value *basePtr = resolveGepFn->getArg(0);
  Value *derivedPtr = resolveGepFn->getArg(1);
  createSanitizerGateBranch(builder, F, 0, NormalBB, GetBaseAndLimitBB);

  builder.SetInsertPoint(GetBaseAndLimitBB);
  Value *baseAndLimit =
      builder.CreateCall(getOrCreateResolveGetBounds(M, cls), {basePtr});
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

  validateIR(resolveGepFn);
  recordPatchFunction(resolveGepFn);
  return resolveGepFn;
}

void instrumentGep(Function *F) {
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

    if (gep->getMetadata("cve.noinstrument")) {
      return;
    }

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
    BoundsClass cls = classifyPointer(basePtr);
    auto resolveGepCall = builder.CreateCall(getOrCreateResolveGep(F, cls),
                                             {basePtr, derivedPtr});

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

void instrumentMemcpy(Function *F,
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

    BoundsClass srcCls = classifyPointer(srcPtr);
    BoundsClass dstCls = classifyPointer(dstPtr);
    auto memcpyFn =
        getOrCreateBoundsCheckMemcpySanitizer(F, strategy, srcCls, dstCls);
    auto memcpyCall = builder.CreateCall(memcpyFn, {dstPtr, srcPtr, sizeArg});
    Inst->replaceAllUsesWith(memcpyCall);
    Inst->eraseFromParent();
  }
}

void instrumentMemset(Function *F,
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

    BoundsClass cls = classifyPointer(basePtr);
    auto memsetFn = getOrCreateBoundsCheckMemsetSanitizer(F, strategy, cls);
    auto memsetCall =
        builder.CreateCall(memsetFn, {basePtr, valueArg, sizeArg});
    Inst->replaceAllUsesWith(memsetCall);
    Inst->eraseFromParent();
  }
}

void instrumentMemmove(Function *F,
                       Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<Instruction *> memmoveList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (isa<MemMoveInst>(&inst)) {
        memmoveList.push_back(&inst);
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

      if (fnName == "memmove") {
        memmoveList.push_back(call);
      }
    }
  }

  for (auto Inst : memmoveList) {
    builder.SetInsertPoint(Inst);

    Value *dstPtr = nullptr;
    Value *srcPtr = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemMoveInst>(Inst)) {
      dstPtr = MI->getDest();
      srcPtr = MI->getSource();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(Inst)) {
      dstPtr = MC->getArgOperand(0);
      srcPtr = MC->getArgOperand(1);
      sizeArg = MC->getArgOperand(2);
    }

    BoundsClass srcCls = classifyPointer(srcPtr);
    BoundsClass dstCls = classifyPointer(dstPtr);
    auto memmoveFn =
        getOrCreateBoundsCheckMemmoveSanitizer(F, strategy, srcCls, dstCls);
    auto memmoveCall = builder.CreateCall(memmoveFn, {dstPtr, srcPtr, sizeArg});
    Inst->replaceAllUsesWith(memmoveCall);
    Inst->eraseFromParent();
  }
}

void instrumentLoadStore(Function *F,
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
    llvm::errs() << "[CVEAssert] Error: instrumentLoadStore does not support "
                    "remediation strategy "
                 << "defaulting to continue strategy!\n";
    strategy = Vulnerability::RemediationStrategies::CONTINUE;
    break;
  }

  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (auto *load = dyn_cast<LoadInst>(&I)) {
        if (load->getMetadata("cve.noinstrument")) {
          continue;
        }
        loadList.push_back(load);

      } else if (auto *store = dyn_cast<StoreInst>(&I)) {
        if (store->getMetadata("cve.noinstrument")) {
          continue;
        }
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

    BoundsClass cls = classifyPointer(ptr);
    auto loadFn =
        getOrCreateBoundsCheckLoadSanitizer(F, valueTy, strategy, cls);

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

    BoundsClass cls = classifyPointer(ptr);
    auto storeFn =
        getOrCreateBoundsCheckStoreSanitizer(F, valueTy, strategy, cls);

    auto sanitizedStore =
        builder.CreateCall(storeFn, {ptr, Inst->getValueOperand()});
    Inst->replaceAllUsesWith(sanitizedStore);
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeMemInstBounds(Function *F,
                           Vulnerability::RemediationStrategies strategy) {
  instrumentGep(F);
  instrumentMemcpy(F, strategy);
  instrumentMemmove(F, strategy);
  instrumentMemset(F, strategy);
  instrumentLoadStore(F, strategy);
}
