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
#include "IRUtils.hpp"
#include "Vulnerability.hpp"

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

static FunctionCallee getOrCreateGetBounds(Module *M, BoundsClass cls) {
  auto &Ctx = M->getContext();
  auto ptrType = PointerType::get(Ctx, 0);
  auto structType = StructType::get(Ctx, {ptrType, ptrType}, false);

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
      name, FunctionType::get(structType, {ptrType}, false), attrs);
}

static FunctionCallee getOrCreateReportAccessViolation(Module *M) {
  auto &Ctx = M->getContext();
  auto ptrType = PointerType::get(Ctx, 0);
  auto sizeType = Type::getInt64Ty(Ctx);
  auto voidType = Type::getVoidTy(Ctx);
  return M->getOrInsertFunction(
      "__resolve_report_violation",
      FunctionType::get(voidType, {ptrType, sizeType, ptrType}, false));
}

static Function *getOrCreateAccessOk(Module *M, BoundsClass cls) {
  std::string handlerName = std::string("__resolve_access_ok_") + classTag(cls);
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);
  auto sizeType = Type::getInt64Ty(Ctx);
  auto boolType = Type::getIntNTy(Ctx, 1);

  FunctionType *accessCheckType =
      FunctionType::get(boolType, {ptrType, sizeType, ptrType}, false);

  Function *accessOkFn =
      getOrCreateResolveHelper(M, handlerName, accessCheckType);

  if (!accessOkFn->empty()) {
    recordPatchFunction(accessOkFn);
    return accessOkFn;
  }

  // Adding an attribute to always inline this function
  accessOkFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", accessOkFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", accessOkFn);
  BasicBlock *accessAllowedBB =
      BasicBlock::Create(Ctx, "safe.access", accessOkFn);
  BasicBlock *accessDeniedBB =
      BasicBlock::Create(Ctx, "unsafe.access", accessOkFn);

  builder.SetInsertPoint(entryBB);

  Value *ptr = accessOkFn->getArg(0);
  Value *accessSize = accessOkFn->getArg(1);

  Value *bounds =
      builder.CreateCall(getOrCreateGetBounds(M, cls), {ptr}, "resolve.bounds");
  Value *upperBound = builder.CreateExtractValue(bounds, 1);
  Value *upperBoundInt = builder.CreatePtrToInt(upperBound, sizeType);
  Value *lowerBoundInt = builder.CreatePtrToInt(ptr, sizeType);
  Value *untrackedObject =
      builder.CreateICmpEQ(upperBoundInt, ConstantInt::get(sizeType, 0));
  builder.CreateCondBr(untrackedObject, accessAllowedBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  Value *accessLimit = builder.CreateAdd(
      lowerBoundInt,
      builder.CreateSub(accessSize, ConstantInt::get(sizeType, 1)));

  Value *accessInBounds = builder.CreateICmpULE(accessLimit, upperBoundInt);

  builder.CreateCondBr(accessInBounds, accessAllowedBB, accessDeniedBB);

  builder.SetInsertPoint(accessAllowedBB);
  builder.CreateRet(ConstantInt::getTrue(Ctx));

  builder.SetInsertPoint(accessDeniedBB);
  builder.CreateRet(ConstantInt::getFalse(Ctx));

  validateIR(accessOkFn);
  recordPatchFunction(accessOkFn);
  return accessOkFn;
}

static Function *
getOrCreateLoadWrapper(Function *F, Type *Type,
                       Vulnerability::RemediationStrategies strategy,
                       BoundsClass cls) {
  std::string handlerName =
      "__resolve_bound_ld_" + getLLVMType(Type) + "_" + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);

  FunctionType *wrapperType = FunctionType::get(Type, {ptrType}, false);
  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);

  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", wrapperFn);
  BasicBlock *performLoadBB = BasicBlock::Create(Ctx, "safe.load", wrapperFn);
  BasicBlock *handleInvalidLoadBB =
      BasicBlock::Create(Ctx, "sanitize.load", wrapperFn);

  builder.SetInsertPoint(entryBB);
  Value *ptr = wrapperFn->getArg(0);
  createSanitizerGateBranch(builder, F, 0, performLoadBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  // TODO: Add global variable for function name to be passed into function
  Value *affectedFnName = builder.CreateGlobalStringPtr(F->getName(), "", 0, M);
  Value *accessInBounds = builder.CreateCall(
      getOrCreateAccessOk(M, cls), {ptr, ConstantExpr::getSizeOf(Type)});

  builder.CreateCondBr(accessInBounds, performLoadBB, handleInvalidLoadBB);

  // performLoadBB: Return the loaded value.
  builder.SetInsertPoint(performLoadBB);
  LoadInst *load = builder.CreateLoad(Type, ptr);
  builder.CreateRet(load);

  // handleInvalidLoadBB: Apply remediation strategy
  builder.SetInsertPoint(handleInvalidLoadBB);
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(Constant::getNullValue(Type));
  }

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *
getOrCreateStoreWrapper(Function *F, Type *Type,
                        Vulnerability::RemediationStrategies strategy,
                        BoundsClass cls) {
  std::string handlerName =
      "__resolve_bound_st_" + getLLVMType(Type) + "_" + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptrType = PointerType::get(Ctx, 0);
  auto voidType = Type::getVoidTy(Ctx);

  FunctionType *wrapperType =
      FunctionType::get(voidType, {ptrType, Type}, false);

  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", wrapperFn);
  BasicBlock *performStoreBB = BasicBlock::Create(Ctx, "safe.store", wrapperFn);
  BasicBlock *handleInvalidStoreBB =
      BasicBlock::Create(Ctx, "sanitize.store", wrapperFn);

  builder.SetInsertPoint(entryBB);
  Value *ptr = wrapperFn->getArg(0);
  Value *storedValue = wrapperFn->getArg(1);

  createSanitizerGateBranch(builder, F, 0, performStoreBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  // TODO: Add global variable for affected function name
  Value *affectedFnName = builder.CreateGlobalStringPtr(F->getName());
  Value *accessInBounds = builder.CreateCall(
      getOrCreateAccessOk(M, cls), {ptr, ConstantExpr::getSizeOf(Type)});

  builder.CreateCondBr(accessInBounds, performStoreBB, handleInvalidStoreBB);

  builder.SetInsertPoint(performStoreBB);
  builder.CreateStore(storedValue, ptr);
  builder.CreateRetVoid();

  // handleInvalidStoreBB: Apply remediation strategy
  builder.SetInsertPoint(handleInvalidStoreBB);
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRetVoid();
  }

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *
getOrCreateMemcpyWrapper(Function *F,
                         Vulnerability::RemediationStrategies strategy,
                         BoundsClass srcCls, BoundsClass dstCls) {
  std::string handlerName = std::string("__resolve_memcpy_") +
                            classTag(srcCls) + "_" + classTag(dstCls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);
  auto sizeType = Type::getInt64Ty(Ctx);

  FunctionType *wrapperType =
      FunctionType::get(ptrType, {ptrType, ptrType, sizeType}, false);

  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", wrapperFn);
  BasicBlock *performMemmoveBB =
      BasicBlock::Create(Ctx, "safe.memcpy", wrapperFn);
  BasicBlock *SanitizeMemcpyBB =
      BasicBlock::Create(Ctx, "sanitize.memcpy", wrapperFn);

  builder.SetInsertPoint(entryBB);
  // Extract dst, src, size arguments from function
  Value *dstPtr = wrapperFn->getArg(0);
  Value *srcPtr = wrapperFn->getArg(1);
  Value *sizeArg = wrapperFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, performMemmoveBB, checkBoundsBB);

  // TODO: Get name of the affected function
  Value *affectedFnName;

  builder.SetInsertPoint(checkBoundsBB);
  Value *checkSrcBounds =
      builder.CreateCall(getOrCreateAccessOk(M, srcCls), {srcPtr, sizeArg});
  Value *checkDstBounds =
      builder.CreateCall(getOrCreateAccessOk(M, dstCls), {dstPtr, sizeArg});

  Value *accessInBounds = builder.CreateAnd(checkSrcBounds, checkDstBounds);
  builder.CreateCondBr(accessInBounds, performMemmoveBB, SanitizeMemcpyBB);

  // performMemmoveBB: Call memcpy and return the ptr
  builder.SetInsertPoint(performMemmoveBB);
  FunctionCallee memcpyFn = M->getOrInsertFunction(
      "memcpy",
      FunctionType::get(ptrType, {ptrType, ptrType, sizeType}, false));
  Value *memcpyPtr = builder.CreateCall(memcpyFn, {dstPtr, srcPtr, sizeArg});
  builder.CreateRet(memcpyPtr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemcpyBB);
  builder.CreateCall(getOrCreateReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(dstPtr);
  }
  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *
getOrCreateMemmoveWrapper(Function *F,
                          Vulnerability::RemediationStrategies strategy,
                          BoundsClass srcCls, BoundsClass dstCls) {
  std::string handlerName = std::string("__resolve_memmove_") +
                            classTag(srcCls) + "_" + classTag(dstCls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);
  auto sizeType = Type::getInt64Ty(Ctx);

  FunctionType *wrapperType =
      FunctionType::get(ptrType, {ptrType, ptrType, sizeType}, false);

  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", wrapperFn);
  BasicBlock *performMemmoveBB =
      BasicBlock::Create(Ctx, "safe.memmove", wrapperFn);
  BasicBlock *handleInvalidMemmoveBB =
      BasicBlock::Create(Ctx, "sanitize.memmove", wrapperFn);

  builder.SetInsertPoint(entryBB);
  // Extract dst, src, size arguments from function
  Value *dstPtr = wrapperFn->getArg(0);
  Value *srcPtr = wrapperFn->getArg(1);
  Value *sizeArg = wrapperFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, performMemmoveBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  Value *checkSrcBounds =
      builder.CreateCall(getOrCreateAccessOk(M, srcCls), {srcPtr, sizeArg});
  Value *checkDstBounds =
      builder.CreateCall(getOrCreateAccessOk(M, dstCls), {dstPtr, sizeArg});

  Value *accessInBounds = builder.CreateAnd(checkSrcBounds, checkDstBounds);
  builder.CreateCondBr(accessInBounds, performMemmoveBB,
                       handleInvalidMemmoveBB);

  // performMemmoveBB: Call memcpy and return the ptr
  builder.SetInsertPoint(performMemmoveBB);
  FunctionCallee memmoveFn = M->getOrInsertFunction(
      "memmove",
      FunctionType::get(ptrType, {ptrType, ptrType, sizeType}, false));
  Value *memmovePtr = builder.CreateCall(memmoveFn, {dstPtr, srcPtr, sizeArg});
  builder.CreateRet(memmovePtr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(handleInvalidMemmoveBB);
  builder.CreateCall(getOrCreateReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(dstPtr);
  }

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *
getOrCreateMemsetWrapper(Function *F,
                         Vulnerability::RemediationStrategies strategy,
                         BoundsClass cls) {
  std::string handlerName = std::string("__resolve_memset_") + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);
  auto intType = Type::getInt32Ty(Ctx);
  auto sizeType = Type::getInt64Ty(Ctx);

  FunctionType *wrapperType =
      FunctionType::get(ptrType, {ptrType, intType, sizeType}, false);

  Function *wrapperFn = getOrCreateResolveHelper(M, handlerName, wrapperType);
  if (!wrapperFn->empty()) {
    recordPatchFunction(wrapperFn);
    return wrapperFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", wrapperFn);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", wrapperFn);
  BasicBlock *performMemmoveBB =
      BasicBlock::Create(Ctx, "safe.memset", wrapperFn);
  BasicBlock *handleInvalidMemsetBB =
      BasicBlock::Create(Ctx, "sanitize.memset", wrapperFn);

  builder.SetInsertPoint(entryBB);
  // Extract arguments for memset
  Value *ptr = wrapperFn->getArg(0);
  Value *valueArg = wrapperFn->getArg(1);
  Value *accessSize = wrapperFn->getArg(2);

  createSanitizerGateBranch(builder, F, 0, performMemmoveBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  Value *checkDstBounds =
      builder.CreateCall(getOrCreateAccessOk(M, cls), {ptr, accessSize});
  builder.CreateCondBr(checkDstBounds, performMemmoveBB, handleInvalidMemsetBB);

  // performMemmoveBB: call memset and return the pointer
  builder.SetInsertPoint(performMemmoveBB);

  FunctionCallee memsetFn = M->getOrInsertFunction(
      "memset",
      FunctionType::get(ptrType, {ptrType, intType, sizeType}, false));

  Value *memsetPtr = builder.CreateCall(memsetFn, {ptr, valueArg, accessSize});
  builder.CreateRet(memsetPtr);

  builder.SetInsertPoint(handleInvalidMemsetBB);
  builder.CreateCall(getOrCreateReportSanitizerTriggered(M));
  if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
    builder.CreateCall(fn);
    builder.CreateUnreachable();
  } else {
    builder.CreateRet(ptr);
  }

  validateIR(wrapperFn);
  recordPatchFunction(wrapperFn);
  return wrapperFn;
}

static Function *getOrCreateGepWrapper(Function *F, BoundsClass cls) {
  std::string handlerName = std::string("__resolve_gep_") + classTag(cls);
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptrType = PointerType::get(Ctx, 0);
  auto sizeType = Type::getInt64Ty(Ctx);

  FunctionType *gepWrapperType =
      FunctionType::get(ptrType, {ptrType, ptrType}, false);

  Function *gepWrapper =
      getOrCreateResolveHelper(M, handlerName, gepWrapperType);
  if (!gepWrapper->empty()) {
    recordPatchFunction(gepWrapper);
    return gepWrapper;
  }

  // Adding attribute to always inline
  gepWrapper->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", gepWrapper);
  BasicBlock *getBoundsBB = BasicBlock::Create(Ctx, "get.bounds", gepWrapper);
  BasicBlock *checkBoundsBB =
      BasicBlock::Create(Ctx, "check.access", gepWrapper);
  BasicBlock *inBoundsBB = BasicBlock::Create(Ctx, "ptr.inbounds", gepWrapper);
  BasicBlock *onePastBB = BasicBlock::Create(Ctx, "ptr.oob", gepWrapper);

  builder.SetInsertPoint(entryBB);
  // Extract the base and derived pointer
  Value *rootPtr = gepWrapper->getArg(0);
  Value *derivedPtr = gepWrapper->getArg(1);
  createSanitizerGateBranch(builder, F, 0, inBoundsBB, getBoundsBB);

  builder.SetInsertPoint(getBoundsBB);
  Value *bounds = builder.CreateCall(getOrCreateGetBounds(M, cls), {rootPtr});
  Value *lowerBound = builder.CreateExtractValue(bounds, 0);
  Value *upperBound = builder.CreateExtractValue(bounds, 1);

  Value *lowerBoundInt = builder.CreatePtrToInt(lowerBound, sizeType);
  Value *upperBoundInt = builder.CreatePtrToInt(upperBound, sizeType);
  Value *isSentinel =
      builder.CreateICmpEQ(upperBoundInt, ConstantInt::get(sizeType, 0));
  builder.CreateCondBr(isSentinel, inBoundsBB, checkBoundsBB);

  builder.SetInsertPoint(checkBoundsBB);
  Value *derivedInt = builder.CreatePtrToInt(derivedPtr, sizeType);
  Value *underLimit = builder.CreateICmpULE(derivedInt, upperBoundInt);
  Value *aboveBase = builder.CreateICmpUGE(derivedInt, lowerBoundInt);
  Value *accessInBounds = builder.CreateAnd(underLimit, aboveBase);

  builder.CreateCondBr(accessInBounds, inBoundsBB, onePastBB);

  builder.SetInsertPoint(inBoundsBB);
  builder.CreateRet(derivedPtr);

  builder.SetInsertPoint(onePastBB);

  // Return a pointer that is clamped at one past the last valid byte address
  Value *onePastInt =
      builder.CreateAdd(upperBoundInt, ConstantInt::get(sizeType, 1));
  Value *onePastPtr = builder.CreateIntToPtr(onePastInt, ptrType);
  builder.CreateRet(onePastPtr);

  validateIR(gepWrapper);
  recordPatchFunction(gepWrapper);
  return gepWrapper;
}

void instrumentGep(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();
  SmallVector<GetElementPtrInst *> gepList;
  std::unordered_set<GetElementPtrInst *> visitedGep;

  auto handle_gep = [&](auto *gep) {
    if (visitedGep.contains(gep)) {
      return;
    }

    if (gep->getMetadata("cve.noinstrument")) {
      return;
    }

    Value *ptr = gep->getPointerOperand();
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
    BoundsClass cls = classifyPointer(ptr);
    auto resolveGepCall =
        builder.CreateCall(getOrCreateGepWrapper(F, cls), {ptr, derivedPtr});

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
  SmallVector<Instruction *> memcpyList;

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

      Function *callee = call->getCalledFunction();
      if (!callee) {
        continue;
      }

      StringRef fnName = callee->getName();

      if (fnName == "memcpy") {
        memcpyList.push_back(call);
      }
    }
  }

  for (auto *memcpy : memcpyList) {
    builder.SetInsertPoint(memcpy);

    Value *dstPtr = nullptr;
    Value *srcPtr = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemCpyInst>(memcpy)) {
      dstPtr = MI->getDest();
      srcPtr = MI->getSource();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(memcpy)) {
      dstPtr = MC->getArgOperand(0);
      srcPtr = MC->getArgOperand(1);
      sizeArg = MC->getArgOperand(2);
    }

    BoundsClass srcCls = classifyPointer(srcPtr);
    BoundsClass dstCls = classifyPointer(dstPtr);
    auto wrapperFn = getOrCreateMemcpyWrapper(F, strategy, srcCls, dstCls);
    auto wrapperCall = builder.CreateCall(wrapperFn, {dstPtr, srcPtr, sizeArg});
    memcpy->replaceAllUsesWith(wrapperCall);
    memcpy->eraseFromParent();
  }
}

void instrumentMemset(Function *F,
                      Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  SmallVector<Instruction *> memsetList;

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

      Function *callee = call->getCalledFunction();
      if (!callee) {
        continue;
      }

      StringRef fnName = callee->getName();

      if (fnName == "memset") {
        memsetList.push_back(call);
      }
    }
  }

  for (auto *memset : memsetList) {
    builder.SetInsertPoint(memset);

    Value *ptr = nullptr;
    Value *valueArg = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemSetInst>(memset)) {
      ptr = MI->getDest();
      valueArg = MI->getValue();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(memset)) {
      ptr = MC->getArgOperand(0);
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

    BoundsClass cls = classifyPointer(ptr);
    auto wrapperFn = getOrCreateMemsetWrapper(F, strategy, cls);
    auto wrapperCall = builder.CreateCall(wrapperFn, {ptr, valueArg, sizeArg});
    memset->replaceAllUsesWith(wrapperCall);
    memset->eraseFromParent();
  }
}

void instrumentMemmove(Function *F,
                       Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  SmallVector<Instruction *> memmoveList;

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

      Function *callee = call->getCalledFunction();
      if (!callee) {
        continue;
      }

      StringRef fnName = callee->getName();

      if (fnName == "memmove") {
        memmoveList.push_back(call);
      }
    }
  }

  for (auto *memmove : memmoveList) {
    builder.SetInsertPoint(memmove);

    Value *dstPtr = nullptr;
    Value *srcPtr = nullptr;
    Value *sizeArg = nullptr;

    if (auto *MI = dyn_cast<MemMoveInst>(memmove)) {
      dstPtr = MI->getDest();
      srcPtr = MI->getSource();
      sizeArg = MI->getLength();
    } else if (auto *MC = dyn_cast<CallInst>(memmove)) {
      dstPtr = MC->getArgOperand(0);
      srcPtr = MC->getArgOperand(1);
      sizeArg = MC->getArgOperand(2);
    }

    BoundsClass srcCls = classifyPointer(srcPtr);
    BoundsClass dstCls = classifyPointer(dstPtr);
    auto wrapperFn = getOrCreateMemmoveWrapper(F, strategy, srcCls, dstCls);
    auto wrapperCall = builder.CreateCall(wrapperFn, {dstPtr, srcPtr, sizeArg});
    memmove->replaceAllUsesWith(wrapperCall);
    memmove->eraseFromParent();
  }
}

void instrumentLoadStore(Function *F,
                         Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  SmallVector<LoadInst *> loadList;
  SmallVector<StoreInst *> storeList;

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

  for (auto *load : loadList) {
    builder.SetInsertPoint(load);
    auto ptr = load->getPointerOperand();
    auto valueType = load->getType();

    // Skip trivially correct accesses to stack values in this function (i.e.,
    // most automatic variables) Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueType)
        continue;
    }

    BoundsClass cls = classifyPointer(ptr);
    auto wrapperFn = getOrCreateLoadWrapper(F, valueType, strategy, cls);

    auto wrapperCall = builder.CreateCall(wrapperFn, {ptr});
    load->replaceAllUsesWith(wrapperCall);
    load->removeFromParent();
    load->deleteValue();
  }

  for (auto *store : storeList) {
    builder.SetInsertPoint(store);
    auto ptr = store->getPointerOperand();
    auto valueType = store->getValueOperand()->getType();

    // Skip trivially correct accesses to stack values in this function (i.e.,
    // most automatic variables) Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueType)
        continue;
    }

    BoundsClass cls = classifyPointer(ptr);
    auto wrapperFn = getOrCreateStoreWrapper(F, valueType, strategy, cls);

    auto wrapperCall =
        builder.CreateCall(wrapperFn, {ptr, store->getValueOperand()});
    store->replaceAllUsesWith(wrapperCall);
    store->removeFromParent();
    store->deleteValue();
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
