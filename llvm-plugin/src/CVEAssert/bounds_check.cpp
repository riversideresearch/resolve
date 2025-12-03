/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include "Worklist.hpp"
#include "Vulnerability.hpp"
#include "helpers.hpp"

static const bool FIND_PTR_ROOT_DEBUG = true;

#include <map>

using namespace llvm;

static Function *getOrCreateBoundsCheckLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_ld_" + getLLVMType(ty);
  SmallVector<char> handlerNameStr;

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr))) {
    return handler;
  }

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *sanitizeLoadFnTy = FunctionType::get(
    ty,
    { ptr_ty },
    false
  );

  Function *sanitizeLoadFn = Function::Create(
    sanitizeLoadFnTy,
    Function::InternalLinkage,
    handlerName,
    M
  );

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);
  BasicBlock *NormalLoadBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);
  BasicBlock *SanitizeLoadBB = BasicBlock::Create(Ctx, "", sanitizeLoadFn);
  
  // Call simplified resolve-check-bounds on pointer if not in sobj table call remediation strategy 
  FunctionType *resolveCheckBoundsFnTy = FunctionType::get(
    Type::getInt1Ty(Ctx),
    { ptr_ty, size_ty },
    false
  );

  FunctionCallee resolveCheckBoundsFn = M->getOrInsertFunction(
    "resolve_check_bounds",
    resolveCheckBoundsFnTy
  );

  Value *basePtr = sanitizeLoadFn->getArg(0); 

  builder.SetInsertPoint(EntryBB);
  Value *withinBounds = builder.CreateCall(resolveCheckBoundsFn, { basePtr, ConstantExpr::getSizeOf(ty) });

  builder.CreateCondBr(withinBounds, NormalLoadBB, SanitizeLoadBB);

  // NormalLoadBB: Return the loaded value.
  builder.SetInsertPoint(NormalLoadBB);
  LoadInst *load = builder.CreateLoad(ty, basePtr);
  builder.CreateRet(load);

  // SanitizeLoadBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeLoadBB);
  switch (strategy) {
    case Vulnerability::RemediationStrategies::EXIT:
      builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
      builder.CreateUnreachable();
      break;
  }

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeLoadFn;
  if (verifyFunction(*sanitizeLoadFn, &out)) {
  }

  return sanitizeLoadFn;
}

static Function *getOrCreateBoundsCheckStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Value *storedVal, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_st_" + getLLVMType(ty);
  SmallVector<char> handlerNameStr;

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);
  
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *sanitizeStoreFnTy = FunctionType::get(
    void_ty,
    { ptr_ty, ty },
    false
  );

  Function *sanitizeStoreFn = Function::Create(
    sanitizeStoreFnTy,
    Function::InternalLinkage,
    handlerName,
    M
  );

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);
  BasicBlock *NormalStoreBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);
  BasicBlock *SanitizeStoreBB = BasicBlock::Create(Ctx, "", sanitizeStoreFn);

  FunctionType *resolveCheckBoundsFnTy = FunctionType::get(
    Type::getInt1Ty(Ctx),
    { ptr_ty, size_ty },
    false
  );

  FunctionCallee resolveCheckBoundsFn = M->getOrInsertFunction(
    "resolve_check_bounds",
    resolveCheckBoundsFnTy
  );

  Value *basePtr = sanitizeStoreFn->getArg(0);
  builder.SetInsertPoint(EntryBB);

  Value *withinBounds = builder.CreateCall(resolveCheckBoundsFn,
      { basePtr, ConstantExpr::getSizeOf(ty) });
  
  builder.CreateCondBr(withinBounds, NormalStoreBB, SanitizeStoreBB);

  // NormalStoreBB: Store value @ addr
  builder.SetInsertPoint(NormalStoreBB);
  StoreInst *store = builder.CreateStore(storedVal, basePtr);
  builder.CreateRetVoid();

  // SanitizeStoreBB: Apply remediation strategy
  builder.SetInsertPoint(SanitizeStoreBB);
  switch(strategy) {
    case Vulnerability::RemediationStrategies::EXIT:
      builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
      builder.CreateUnreachable();
      break;
  }
  
  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeStoreFn;
  if (verifyFunction(*sanitizeStoreFn, &out)) {
  }

  return sanitizeStoreFn;
}

static Function *getOrCreateBoundsCheckMemcpySanitizer(Module *M, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_memcpy";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();
  
  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);
  
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  // void *resolve_memcpy(void *dst, void *derived_dst, void *src, void* derived_src, size_t n)
  // - dst: pointer to destination memory area where the content is to be copied  
  // - dst_derived: offset of dst + n 
  // - src: pointer to source memory area where content is to be copied
  // - src_derived: offset of src + n

  FunctionType *sanitizeMemcpyFnTy = FunctionType::get(
    ptr_ty, {ptr_ty, ptr_ty, size_ty}, false);

  Function *sanitizeMemcpyFn = Function::Create(
    sanitizeMemcpyFnTy,
    Function::InternalLinkage,
    handlerName,
    M
  );

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);
  BasicBlock *NormalBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);
  BasicBlock *SanitizeMemcpyBB = BasicBlock::Create(Ctx, "", sanitizeMemcpyFn);

  FunctionType *resolveCheckBoundsFnTy = FunctionType::get(
    Type::getInt1Ty(Ctx),
    { ptr_ty, size_ty },
    false
  );

  FunctionCallee resolveCheckBoundsFn = M->getOrInsertFunction(
    "resolve_check_bounds",
    resolveCheckBoundsFnTy
  );

  // EntryBB: Call libresolve check_bounds runtime function
  // to verify correct bounds of allocation
  builder.SetInsertPoint(EntryBB);

  // Extract dst, src, size arguments from function
  Value *dst_ptr = sanitizeMemcpyFn->getArg(0);
  Value *src_ptr = sanitizeMemcpyFn->getArg(1);
  Value *size_arg = sanitizeMemcpyFn->getArg(2);

  Value *check_src_bd =
      builder.CreateCall(resolveCheckBoundsFn, { src_ptr, size_arg });
  Value *check_dst_bd =
      builder.CreateCall(resolveCheckBoundsFn, { dst_ptr, size_arg});

  Value *withinBounds = builder.CreateAnd(check_src_bd, check_dst_bd);
  builder.CreateCondBr(withinBounds, NormalBB, SanitizeMemcpyBB);

  // NormalBB: Call libc memcpy and return the pointer
  builder.SetInsertPoint(NormalBB);
  FunctionCallee memcpyfn = M->getOrInsertFunction(
      "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memcpy_ptr =
      builder.CreateCall(memcpyfn, {dst_ptr, src_ptr, size_arg});
  builder.CreateRet(memcpy_ptr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemcpyBB);
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateUnreachable();

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeMemcpyFn;
  if (verifyFunction(*sanitizeMemcpyFn, &out)) {}
  return sanitizeMemcpyFn;
}

void sanitizeAlloca(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();

  // Initialize list to store pointers to alloca and instructions
  std::vector<AllocaInst *> allocaList;
  
  auto void_ty = Type::getVoidTy(Ctx);
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto int64_ty = Type::getInt64Ty(Ctx);

  FunctionType *resolveStackObjFnTy = FunctionType::get(
      void_ty,
      { ptr_ty, int64_ty },
      false
  );
  
  /* Initialize function callee object for libresolve resolve_stack_obj runtime fn */
  FunctionCallee resolveStackObjFn = M->getOrInsertFunction(
      "resolve_stack_obj",
      resolveStackObjFnTy   
  );

  for (auto &BB: *F) {
      for (auto &instr: BB) {
          if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
              allocaList.push_back(inst);
          }
      }
  }

  for (auto* allocaInst: allocaList) {
      // Insert after the alloca instruction
      builder.SetInsertPoint(allocaInst->getNextNode());
      Value* allocatedPtr = allocaInst;

      Value *sizeVal = nullptr;
      Type *allocatedType = allocaInst->getAllocatedType();
      uint64_t typeSize = DL.getTypeAllocSize(allocatedType); 
      sizeVal = ConstantInt::get(int64_ty, typeSize);
      builder.CreateCall(resolveStackObjFn, { allocatedPtr, sizeVal });
      
  }
}

void sanitizeMalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> mallocList;

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  FunctionType *resolveMallocFnTy = FunctionType::get(ptr_ty,
    { size_ty }, 
    false
  );

  FunctionCallee resolveMallocFn = M->getOrInsertFunction(
    "resolve_malloc",
    resolveMallocFnTy
  );

  for (auto &BB : *F) {
    for (auto &inst: BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) { continue; }

        StringRef fnName = calledFn->getName();
        
        if (fnName == "malloc") { mallocList.push_back(call); }
      }
    }
  }

  for (auto Inst : mallocList) {
    builder.SetInsertPoint(Inst);
    Value *arg = Inst->getArgOperand(0);
    Value *normalizeArg = builder.CreateZExtOrBitCast(arg, size_ty);
    CallInst *resolveMallocCall = builder.CreateCall(resolveMallocFn, { normalizeArg });
    Inst->replaceAllUsesWith(resolveMallocCall);
    Inst->eraseFromParent();  
  }
}

void sanitizeGEP(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();
  std::vector<GetElementPtrInst *> gepList;
  auto ptr_ty = PointerType::get(Ctx, 0);

  FunctionType *resolveGEPFnTy = FunctionType::get(
    ptr_ty,
    { ptr_ty, ptr_ty },
    false
  );

  FunctionCallee resolveGEPFn = M->getOrInsertFunction(
    "resolve_gep",
    resolveGEPFnTy
  );

  for (auto &BB : *F) {
    for (auto &inst: BB) {
      if (auto *gep = dyn_cast<GetElementPtrInst>(&inst)) {
        gepList.push_back(gep);
      }
    }
  }

  for (auto GEPInst: gepList) {
    builder.SetInsertPoint(GEPInst->getNextNode());

    // Get the pointer operand and offset from GEP
    Value *basePtr = GEPInst->getPointerOperand();
    Value * derivedPtr = GEPInst;

    auto resolveGEPCall = builder.CreateCall(resolveGEPFn, { basePtr, derivedPtr });

    // Collect users of gep instruction before mutation
    SmallVector<User*, 8> gep_users;
    for (User *U : GEPInst->users()) {
      gep_users.push_back(U);
    }

    // Iterate over all the users of the gep instruction and 
    // replace there operands with resolve_gep result 
    for (User *U : gep_users) {
      if (U != resolveGEPCall) {
        U->replaceUsesOfWith(GEPInst, resolveGEPCall);
      }
    }
  }
}

void sanitizeMemcpy(Function *F, Vulnerability::RemediationStrategies strategy) {
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<MemCpyInst *> memcpyList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *memcpyInst = dyn_cast<MemCpyInst>(&inst)) {
        memcpyList.push_back(memcpyInst);
      }
    }
  }

  for (auto Inst : memcpyList) {
    builder.SetInsertPoint(Inst);
    auto dst_ptr = Inst->getDest();
    auto src_ptr = Inst->getSource();
    auto size_arg = Inst->getLength();
    auto memcpyFn = getOrCreateBoundsCheckMemcpySanitizer(F->getParent(), strategy);

    auto sanitized_memcpy = builder.CreateCall(
        memcpyFn, { dst_ptr, src_ptr, size_arg });
    Inst->replaceAllUsesWith(sanitized_memcpy);
    Inst->eraseFromParent();
  }
}

void sanitizeLoadStore(Function *F, Vulnerability::RemediationStrategies strategy) 
{
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<LoadInst *> loadList;
  std::vector<StoreInst *> storeList;

  switch(strategy) {
    //case Vulnerability::RemediationStrategies::CONTINUE-WRAP: /* TODO: Not yet supported. Implement this remediaion strategy */
    //case Vulnerability::RemediationStrategies::CONTINUE-ZERO: /* TODO: Not yet supported. Implement this remediation strategy */
    case Vulnerability::RemediationStrategies::EXIT:
    case Vulnerability::RemediationStrategies::RECOVER:
    case Vulnerability::RemediationStrategies::SAT:                     /* TODO: Not yet supported. Implement this remediation strategy */
      break;

    default:
      llvm::errs() << "[CVEAssert] Error: sanitizeLoadStore does not support remediation strategy "
                   << "defaulting to EXIT strategy!\n";
      strategy = Vulnerability::RemediationStrategies::EXIT;
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
    if (getLLVMType(valueTy) == "") {
      errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy
             << "\n";
      continue;
    }

    auto loadFn = getOrCreateBoundsCheckLoadSanitizer(F->getParent(),
                                                      F->getContext(), valueTy, strategy);

    auto sanitizedLoad = builder.CreateCall(loadFn, { ptr });
    Inst->replaceAllUsesWith(sanitizedLoad);
    Inst->removeFromParent();
    Inst->deleteValue();
  }

  for (auto Inst: storeList) {
    builder.SetInsertPoint(Inst);
    auto ptr = Inst->getPointerOperand();
    auto valueTy = Inst->getValueOperand()->getType();

    if (getLLVMType(valueTy) == "") {
      errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy
             << "\n";
      continue;
    }

    auto storeFn = getOrCreateBoundsCheckStoreSanitizer(
      F->getParent(), F->getContext(), valueTy, Inst->getValueOperand(), strategy
    );

    auto sanitizedStore = builder.CreateCall(storeFn, { ptr, Inst->getValueOperand() });
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeMemInstBounds(Function *F, ModuleAnalysisManager &MAM, Vulnerability::RemediationStrategies strategy) {
  sanitizeAlloca(F);
  sanitizeMalloc(F);
  sanitizeGEP(F);
  sanitizeMemcpy(F, strategy);
  sanitizeLoadStore(F, strategy);
}