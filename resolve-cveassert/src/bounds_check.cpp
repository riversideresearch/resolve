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

#include "CVEAssert.hpp"
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
  std::string handlerName = "resolve_access_ok";
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto bool_ty = Type::getIntNTy(Ctx, 1);

  FunctionType *resolveAccessOkFnTy =
      FunctionType::get(bool_ty, {ptr_ty, size_ty}, false);

  Function *resolveAccessOkFn = getOrCreateResolveHelper(M, handlerName, resolveAccessOkFnTy);

  if (!resolveAccessOkFn->empty()) { return resolveAccessOkFn; }

  // Adding an attribute to always inline this function
  resolveAccessOkFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveAccessOkFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "check_access", resolveAccessOkFn);
  BasicBlock *TrueBB = BasicBlock::Create(Ctx, "return_true", resolveAccessOkFn);
  BasicBlock *FalseBB = BasicBlock::Create(Ctx, "return_false", resolveAccessOkFn);

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

  validateIR(resolveAccessOkFn);
  return resolveAccessOkFn;
}

static Function *getOrCreateBoundsCheckLoadSanitizer(
    Module *M, LLVMContext &Ctx, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_ld_" + getLLVMType(ty);

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveLoadFnTy = FunctionType::get(ty, {ptr_ty}, false);

  Function *resolveLoadFn = getOrCreateResolveHelper(M, handlerName, resolveLoadFnTy);

  if (!resolveLoadFn->empty()) { return resolveLoadFn; }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveLoadFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "check_access", resolveLoadFn);
  BasicBlock *NormalLoadBB = BasicBlock::Create(Ctx, "normal_load", resolveLoadFn);
  BasicBlock *SanitizeLoadBB = BasicBlock::Create(Ctx, "sanitize_load", resolveLoadFn);

  Value *basePtr = resolveLoadFn->getArg(0);

  builder.SetInsertPoint(EntryBB);

  Value *idx = builder.getInt64(0);
  Value* sanitizerMapPtr = builder.CreateGEP(ArrayType::get((i1_ty), 7),
   initSanitizerMap(M), { idx }
  );
  Value* mapValue = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  Value *isZero = builder.CreateICmpEQ(mapValue, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalLoadBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
  Value *withinBounds = builder.CreateCall(
    getOrCreateResolveAccessOk(M), { basePtr, ConstantExpr::getSizeOf(ty)}
  );
 
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

  validateIR(resolveLoadFn);
  return resolveLoadFn;
}

static Function *getOrCreateBoundsCheckStoreSanitizer(
    Module *M, LLVMContext &Ctx, Type *ty,
    Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_st_" + getLLVMType(ty);

  IRBuilder<> builder(Ctx);

  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveStoreFnTy =
      FunctionType::get(void_ty, {ptr_ty, ty}, false);

  Function *resolveStoreFn = getOrCreateResolveHelper(M, handlerName, resolveStoreFnTy);
  if (!resolveStoreFn->empty()) { return resolveStoreFn; }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveStoreFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "check_aceess", resolveStoreFn);
  BasicBlock *NormalStoreBB = BasicBlock::Create(Ctx, "normal_store", resolveStoreFn);
  BasicBlock *SanitizeStoreBB = BasicBlock::Create(Ctx, "sanitize_store", resolveStoreFn);

  Value *basePtr = resolveStoreFn->getArg(0);
  Value *storedVal = resolveStoreFn->getArg(1);
  builder.SetInsertPoint(EntryBB);

  Value *idx = builder.getInt64(0);
  Value* sanitizerMapPtr = builder.CreateGEP(ArrayType::get((i1_ty), 7),
   initSanitizerMap(M), { idx }
  );
  Value* mapValue = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  Value *isZero = builder.CreateICmpEQ(mapValue, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalStoreBB, CheckAccessBB);

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

  validateIR(resolveStoreFn);
  return resolveStoreFn;
}

static Function *getOrCreateBoundsCheckMemcpySanitizer(
    Module *M, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_memcpy";
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveMemcpyFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false);

  Function *resolveMemcpyFn = getOrCreateResolveHelper(M, handlerName, resolveMemcpyFnTy);
  if (!resolveMemcpyFn->empty()) { return resolveMemcpyFn; }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveMemcpyFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "check_access", resolveMemcpyFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "safe_memcpy", resolveMemcpyFn);
  BasicBlock *SanitizeMemcpyBB = BasicBlock::Create(Ctx, "sanitize_memcpy", resolveMemcpyFn);

  // EntryBB: Call resolve_access_ok
  // to verify correct bounds of allocation
  builder.SetInsertPoint(EntryBB);

  // Extract dst, src, size arguments from function
  Value *dst_ptr = resolveMemcpyFn->getArg(0);
  Value *src_ptr = resolveMemcpyFn->getArg(1);
  Value *size_arg = resolveMemcpyFn->getArg(2);

  Value *idx = builder.getInt64(0);
  Value* sanitizerMapPtr = builder.CreateGEP(ArrayType::get((i1_ty), 7),
   initSanitizerMap(M), { idx }
  );
  Value* mapValue = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  Value *isZero = builder.CreateICmpEQ(mapValue, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalBB, CheckAccessBB);

  builder.SetInsertPoint(CheckAccessBB);
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

  validateIR(resolveMemcpyFn);
  return resolveMemcpyFn;
}

static Function *getOrCreateBoundsCheckMemsetSanitizer(
    Module *M, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_memset";
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i32_ty = Type::getInt32Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveMemsetFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, i32_ty, size_ty}, false);

  Function *resolveMemsetFn = getOrCreateResolveHelper(M, handlerName, resolveMemsetFnTy);
  if (!resolveMemsetFn->empty()) { return resolveMemsetFn; } 

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveMemsetFn);
  BasicBlock *CheckAccessBB = BasicBlock::Create(Ctx, "check_access", resolveMemsetFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "safe_memset", resolveMemsetFn);
  BasicBlock *SanitizeMemsetBB = BasicBlock::Create(Ctx, "sanitize_memset", resolveMemsetFn);

  builder.SetInsertPoint(EntryBB);

  // Extract arguments for memset
  Value *basePtr = resolveMemsetFn->getArg(0);
  Value *valueArg = resolveMemsetFn->getArg(1);
  Value *accessSize = resolveMemsetFn->getArg(2);

  Value *idx = builder.getInt64(0);
  Value* sanitizerMapPtr = builder.CreateGEP(ArrayType::get((i1_ty), 7),
   initSanitizerMap(M), { idx }
  );
  Value* mapValue = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  Value *isZero = builder.CreateICmpEQ(mapValue, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalBB, CheckAccessBB);
  
  builder.SetInsertPoint(CheckAccessBB);
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

  validateIR(resolveMemsetFn);
  return resolveMemsetFn;
}

static Function *getOrCreateResolveGep(Module *M) {
  std::string handlerName = "resolve_gep";
  LLVMContext &Ctx = M->getContext();

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto i1_ty = Type::getInt1Ty(Ctx);

  FunctionType *resolveGepFnTy =
      FunctionType::get(ptr_ty, {ptr_ty, ptr_ty}, false);

  Function *resolveGepFn = getOrCreateResolveHelper(M, handlerName, resolveGepFnTy);
  if (!resolveGepFn->empty()) { return resolveGepFn; }

  // Adding attribute to always inline
  resolveGepFn->addFnAttr(Attribute::AlwaysInline);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveGepFn);
  BasicBlock *GetBaseAndLimitBB = BasicBlock::Create(Ctx, "get_base_and_limit", resolveGepFn);
  BasicBlock *CheckComputedPtrBB = BasicBlock::Create(Ctx, "check_access", resolveGepFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "return_normal_ptr", resolveGepFn);
  BasicBlock *OnePastBB = BasicBlock::Create(Ctx, "return_tainted_ptr", resolveGepFn);

  // EntryBB: Call libresolve get_base_and_limit
  // to retrieve the last valid byte address of obj
  builder.SetInsertPoint(EntryBB);

  // Extract the base and derived pointer
  Value *basePtr = resolveGepFn->getArg(0);
  Value *derivedPtr = resolveGepFn->getArg(1);

  Value *idx = builder.getInt64(0);
  Value* sanitizerMapPtr = builder.CreateGEP(ArrayType::get((i1_ty), 7),
   initSanitizerMap(M), { idx }
  );
  Value* mapValue = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  Value *isZero = builder.CreateICmpEQ(mapValue, ConstantInt::get(i1_ty, 0));
  builder.CreateCondBr(isZero, NormalBB, GetBaseAndLimitBB);

  builder.SetInsertPoint(GetBaseAndLimitBB);
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

  validateIR(resolveGepFn);
  return resolveGepFn;
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