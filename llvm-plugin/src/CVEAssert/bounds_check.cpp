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
#include <unordered_set>

using namespace llvm;

static Function *getOrCreateBoundsCheckLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_ld_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName)) {
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

static Function *getOrCreateBoundsCheckStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_bounds_check_st_" + getLLVMType(ty);

  if (auto handler = M->getFunction(handlerName)) {
    return handler;
  }

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
  Value *storedVal = sanitizeStoreFn->getArg(1);
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

static Function *getOrCreateBoundsCheckMemcpySanitizer(Module *M, Vulnerability::RemediationStrategies strategy) {
  Twine handlerName = "resolve_bounds_check_memcpy";
  SmallVector<char> handlerNameStr;
  LLVMContext &Ctx = M->getContext();
  
  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> builder(Ctx);
  
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

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

  // NormalBB: Call memcpy and return the ptr
  builder.SetInsertPoint(NormalBB);
  FunctionCallee memcpyfn = M->getOrInsertFunction(
      "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memcpy_ptr =
      builder.CreateCall(memcpyfn, {dst_ptr, src_ptr, size_arg});
  builder.CreateRet(memcpy_ptr);

  // SanitizeMemcpyBB: Remediate memcpy returns null pointer.
  builder.SetInsertPoint(SanitizeMemcpyBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  builder.CreateRet(dst_ptr);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeMemcpyFn;
  if (verifyFunction(*sanitizeMemcpyFn, &out)) {}
  return sanitizeMemcpyFn;
}

static FunctionCallee getResolveMalloc(Module *M) {
    auto &Ctx = M->getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto size_ty = Type::getInt64Ty(Ctx);
    
    return M->getOrInsertFunction(
        "resolve_malloc",
        FunctionType::get(ptr_ty, { size_ty },
        false
      )
    );
}

static FunctionCallee getResolveRealloc(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
    "resolve_realloc",
    FunctionType::get(ptr_ty, { ptr_ty, size_ty },
    false
    )
  );
}

static FunctionCallee getResolveCalloc(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  return M->getOrInsertFunction(
    "resolve_calloc",
    FunctionType::get(ptr_ty, { size_ty, size_ty },
    false
    )
  );
}

static FunctionCallee getResolveStackObj(Module *M) {
    auto &Ctx = M->getContext();
    auto void_ty = Type::getVoidTy(Ctx);
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto size_ty = Type::getInt64Ty(Ctx);
    
    return M->getOrInsertFunction(
        "resolve_stack_obj",
        FunctionType::get(void_ty, { ptr_ty, size_ty },
        false
      )
    );
}

static FunctionCallee getResolveFree(Module *M) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);

  return M->getOrInsertFunction(
    "resolve_free",
    FunctionType::get(void_ty, { ptr_ty },
    false
    )
  );
}

void instrumentAlloca(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  // Initialize list to store pointers to alloca and instructions
  std::vector<AllocaInst *> allocaList;

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
      sizeVal = ConstantInt::get(size_ty, typeSize);
      builder.CreateCall(getResolveStackObj(M), { allocatedPtr, sizeVal });
  }

  // Find low and high allocations and pass to resolve_invaliate_stack
  if (allocaList.empty()) {
    return;
  }

  auto invalidateFn = M->getOrInsertFunction(
    "resolve_invalidate_stack",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty }, false)
  );

  // Stack grows down, so first allocation is high, last is low
  // Hmm.. compiler seems to be reordering the allocas in ways 
  // that break this assumption
  // auto low = allocaList.back();
  // auto high = allocaList.front();
  for (auto &BB: *F) {
    for (auto &instr: BB) {
      if (auto *inst = dyn_cast<ReturnInst>(&instr)) {
        builder.SetInsertPoint(inst);
        // builder.CreateCall(invalidateFn, { low, high });
        for (auto *alloca: allocaList) {
          builder.CreateCall(invalidateFn, { alloca, alloca });
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
    Value *sizeArg = Inst->getArgOperand(0);
    CallInst *resolveMallocCall = builder.CreateCall(getResolveMalloc(M), { sizeArg });
    Inst->replaceAllUsesWith(resolveMallocCall);
    Inst->eraseFromParent();  
  }
}

void instrumentRealloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> reallocList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) { continue; }

        StringRef fnName = calledFn->getName();

        if (fnName == "realloc") { reallocList.push_back(call); } 
      }
    }
  }

  for (auto Inst : reallocList) {
    builder.SetInsertPoint(Inst);
    Value *ptrArg =Inst->getArgOperand(0);
    Value *sizeArg = Inst->getArgOperand(1);
    CallInst *resolveReallocCall = builder.CreateCall(getResolveRealloc(M), { ptrArg, sizeArg });
    Inst->replaceAllUsesWith(resolveReallocCall);
    Inst->eraseFromParent();
  }
}

void instrumentCalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> callocList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) { continue; }

        StringRef fnName = calledFn->getName();
        if (fnName == "calloc") { callocList.push_back(call); }

      }
    }
  }

  for (auto Inst : callocList) {
    builder.SetInsertPoint(Inst);
    Value *numArg = Inst->getArgOperand(0);
    Value *sizeArg = Inst->getArgOperand(1);
    CallInst *resolveCallocCall = builder.CreateCall(getResolveCalloc(M), { numArg, sizeArg });
    Inst->replaceAllUsesWith(resolveCallocCall);
    Inst->eraseFromParent();
  }

}

void instrumentFree(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<CallInst *> freeList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFn = call->getCalledFunction();

        if (!calledFn) { continue; }

        StringRef fnName = calledFn->getName();
        if (fnName == "free") { freeList.push_back(call); }

      }
    }
  }

  for (auto Inst : freeList) {
    builder.SetInsertPoint(Inst);
    Value *ptrArg = Inst->getArgOperand(0);
    CallInst *resolveFreeCall = builder.CreateCall(getResolveFree(M), { ptrArg });
    Inst->replaceAllUsesWith(resolveFreeCall);
    Inst->eraseFromParent();
  }

}

void instrumentGEP(Function *F) {
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
    
    // Don't assume gep is inbounds, otherwise our remdiation risks being optimized away
    GEPInst->setIsInBounds(false);

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
    // case Vulnerability::RemediationStrategies::CONTINUE-WRAP: /* TODO: Not yet supported. Implement this remediaion strategy */
    // case Vulnerability::RemediationStrategies::CONTINUE-ZERO: /* TODO: Not yet supported. Implement this remediation strategy */
    // case Vulnerability::RemediationStrategies::SAT:          /* TODO: Not yet supported. Implement this remediation strategy */
    case Vulnerability::RemediationStrategies::SAFE:
    case Vulnerability::RemediationStrategies::EXIT:
    case Vulnerability::RemediationStrategies::RECOVER:
      break;

    default:
      llvm::errs() << "[CVEAssert] Error: sanitizeLoadStore does not support remediation strategy "
                   << "defaulting to SAFE strategy!\n";
      strategy = Vulnerability::RemediationStrategies::SAFE;
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

    // Skip trivially correct accesses to stack values in this function (i.e., most automatic variables)
    // Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueTy) continue;
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

    // Skip trivially correct accesses to stack values in this function (i.e., most automatic variables)
    // Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == valueTy) continue;
    }

    auto storeFn = getOrCreateBoundsCheckStoreSanitizer(
      F->getParent(), F->getContext(), valueTy, strategy
    );

    auto sanitizedStore = builder.CreateCall(storeFn, { ptr, Inst->getValueOperand() });
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeMemInstBounds(Function *F, Vulnerability::RemediationStrategies strategy) {
  instrumentGEP(F);
  sanitizeMemcpy(F, strategy);
  sanitizeLoadStore(F, strategy);
}