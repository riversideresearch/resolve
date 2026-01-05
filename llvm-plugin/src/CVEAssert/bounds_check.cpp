/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemorySSA.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/MDBuilder.h"
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

static FunctionCallee getResolveGep(Module *M) {
    auto &Ctx = M->getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto size_ty = Type::getInt64Ty(Ctx);
    
    return M->getOrInsertFunction(
        "resolve_gep",
        FunctionType::get(ptr_ty, { ptr_ty, ptr_ty, size_ty }, false)
    );
}

static FunctionCallee getResolveCheckBounds(Module *M) {
    auto &Ctx = M->getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto size_ty = Type::getInt64Ty(Ctx);

    FunctionType *resolveCheckBoundsFnTy = FunctionType::get(
      Type::getInt1Ty(Ctx),
      { ptr_ty, size_ty },
      false
    );

    return M->getOrInsertFunction(
      "resolve_check_bounds",
      resolveCheckBoundsFnTy
    );
}

template<typename CF, typename TF, typename EF>
void verifyPointerThen(Module* M, LLVMContext& Ctx, Vulnerability::RemediationStrategies strategy, IRBuilder<>& builder, Function* hostFn, CF condFn, TF thenFn, EF elseFn) {
  
  BasicBlock *entryBB = BasicBlock::Create(Ctx, "", hostFn);
  BasicBlock *normalBB = BasicBlock::Create(Ctx, "", hostFn);
  BasicBlock *sanitizeBB = BasicBlock::Create(Ctx, "", hostFn);

  builder.SetInsertPoint(entryBB);
  condFn(normalBB, sanitizeBB);

  builder.SetInsertPoint(normalBB);
  thenFn();

  builder.SetInsertPoint(sanitizeBB);
  builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
  builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
  elseFn();
}

static Function * getOrCreateResolveGepSanitizer(Module *M, LLVMContext &Ctx, Vulnerability::RemediationStrategies strategy) {
  std::string handlerName = "resolve_gep_sanitized";

  if (auto handler = M->getFunction(handlerName)) {
    return handler;
  }

  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *sanitizeGepFnTy= FunctionType::get(
    ptr_ty,
    { ptr_ty, ptr_ty, size_ty },
    false
  );

  Function *sanitizeGepFn = Function::Create(
    sanitizeGepFnTy,
    Function::InternalLinkage,
    handlerName,
    M
  );

  // Call simplified resolve-check-bounds on pointer if not in sobj table call remediation strategy 
  auto resolveGepFn = getResolveGep(M);

  Value *basePtr = sanitizeGepFn->getArg(0); 
  Value *derivedPtr = sanitizeGepFn->getArg(1); 
  Value *elSize = sanitizeGepFn->getArg(2); 

  verifyPointerThen(M, Ctx, strategy, builder, sanitizeGepFn,
    [&](auto normal, auto sanitize) {
      Value * gepResult = builder.CreateCall(resolveGepFn, { basePtr, derivedPtr, elSize });
      // resolve_gep will return the derived pointer if it is allowed
      MDBuilder metadata(Ctx);
      // By default llvm assumes pointer equality comparisons are unlikely to be true
      // in our case it is the opposite and they should be always true unless there is an error.
      auto weights = metadata.createBranchWeights(1000000, 1);
      Value * withinBounds = builder.CreateICmpEQ(derivedPtr, gepResult);
      builder.CreateCondBr(withinBounds, normal, sanitize, weights);
    },
    [&]() { 
      builder.CreateRet(derivedPtr);
    },
    [&]() {
      builder.CreateRet(Constant::getNullValue(ptr_ty));
    }
  );

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizeGepFn;
  if (verifyFunction(*sanitizeGepFn, &out)) {
  }

  return sanitizeGepFn;
}

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

  auto resolveCheckBoundsFn = getResolveCheckBounds(M);

  Value *basePtr = sanitizeLoadFn->getArg(0); 

  verifyPointerThen(M, Ctx, strategy, builder, sanitizeLoadFn,
    [&](auto normal, auto sanitize) {
      Value *withinBounds = builder.CreateCall(resolveCheckBoundsFn, { basePtr, ConstantExpr::getSizeOf(ty) });

      builder.CreateCondBr(withinBounds, normal, sanitize);
    },
    [&]() { 
      LoadInst *load = builder.CreateLoad(ty, basePtr);
      builder.CreateRet(load);
    },
    [&]() {
      builder.CreateRet(Constant::getNullValue(ty));
    }
  );

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

  auto resolveCheckBoundsFn = getResolveCheckBounds(M);

  Value *basePtr = sanitizeStoreFn->getArg(0);
  Value *storedVal = sanitizeStoreFn->getArg(1);

  verifyPointerThen(M, Ctx, strategy, builder, sanitizeStoreFn,
    [&](auto normal, auto sanitize) {
      Value *withinBounds = builder.CreateCall(resolveCheckBoundsFn, { basePtr, ConstantExpr::getSizeOf(ty) });

      builder.CreateCondBr(withinBounds, normal, sanitize);
    },
    [&]() { 
      StoreInst *store = builder.CreateStore(storedVal, basePtr);
      builder.CreateRetVoid();
    },
    [&]() {
      builder.CreateRetVoid();
    }
  );
  
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

  auto resolveCheckBoundsFn = getResolveCheckBounds(M);

  // Extract dst, src, size arguments from function
  Value *dst_ptr = sanitizeMemcpyFn->getArg(0);
  Value *src_ptr = sanitizeMemcpyFn->getArg(1);
  Value *size_arg = sanitizeMemcpyFn->getArg(2);

  verifyPointerThen(M, Ctx, strategy, builder, sanitizeMemcpyFn,
    [&](auto normal, auto sanitize) {
      Value *check_src_bd =
          builder.CreateCall(resolveCheckBoundsFn, { src_ptr, size_arg });
      Value *check_dst_bd =
          builder.CreateCall(resolveCheckBoundsFn, { dst_ptr, size_arg});

      Value *withinBounds = builder.CreateAnd(check_src_bd, check_dst_bd);
      builder.CreateCondBr(withinBounds, normal, sanitize);
    },
    [&]() { 
      FunctionCallee memcpyfn = M->getOrInsertFunction(
          "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
      Value *memcpy_ptr =
          builder.CreateCall(memcpyfn, {dst_ptr, src_ptr, size_arg});
      builder.CreateRet(memcpy_ptr);
    },
    [&]() {
      builder.CreateRet(dst_ptr);
    }
  );

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

void instrumentAlloca(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);
  auto void_ty = Type::getVoidTy(Ctx);

  // Initialize list to store pointers to alloca and instructions
  std::vector<AllocaInst *> toFreeList;

  auto invalidateFn = M->getOrInsertFunction(
    "resolve_invalidate_stack",
    FunctionType::get(void_ty, { ptr_ty }, false)
  );

  auto handle_alloca = [&](auto* allocaInst) {
      bool hasStart = false;
      bool hasEnd = false;

      Type *allocatedType = allocaInst->getAllocatedType();
      uint64_t typeSize = DL.getTypeAllocSize(allocatedType); 

      for (auto* user: allocaInst->users()) {
        if( auto* call = dyn_cast<CallInst>(user)) {
          auto called = call->getCalledFunction();
          if (called && called->getName().starts_with("llvm.lifetime.start")) {
            hasStart = true;
            builder.SetInsertPoint(call->getNextNode());
            builder.CreateCall(getResolveStackObj(M), { allocaInst, ConstantInt::get(size_ty, typeSize)});
          }

          if (called && called->getName().starts_with("llvm.lifetime.end")) {
            hasEnd = true;
            builder.SetInsertPoint(call->getNextNode());
            builder.CreateCall(invalidateFn, { allocaInst});
          }
        }
      }

      // This is probably always true unless we are given malformed input.
      assert(hasStart == hasEnd);
      if (hasStart) { return; }
      // Otherwise Insert after the alloca instruction
      builder.SetInsertPoint(allocaInst->getNextNode());
      builder.CreateCall(getResolveStackObj(M), { allocaInst, ConstantInt::get(size_ty, typeSize)});
      // If we have not added an invalidate call already make sure we do so later.
      toFreeList.push_back(allocaInst);
  };

  for (auto &BB: *F) {
    for (auto &instr: BB) {
      if (auto *inst = dyn_cast<AllocaInst>(&instr)) {
          handle_alloca(inst);
      }
    }
  }

  if (toFreeList.empty()) {
    return;
  }

  auto invalidateFn2 = M->getOrInsertFunction(
    "resolve_invalidate_stack_2",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty }, false)
  );

  auto invalidateFn3 = M->getOrInsertFunction(
    "resolve_invalidate_stack_3",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty, ptr_ty }, false)
  );

  auto invalidateFn4 = M->getOrInsertFunction(
    "resolve_invalidate_stack_4",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty, ptr_ty, ptr_ty }, false)
  );

  auto invalidateFn5 = M->getOrInsertFunction(
    "resolve_invalidate_stack_5",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty }, false)
  );

  auto invalidateFn6 = M->getOrInsertFunction(
    "resolve_invalidate_stack_6",
    FunctionType::get(void_ty, { ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty }, false)
  );


  // Try to reduce the number of calls to invalidate each of the stack addrs.
  // the x64 ABI allows us to pass up to 6 arguments in registers, so libresolve provides functions with up to arity 6.
  auto invalidate_all_at = [&](auto* inst) {
    builder.SetInsertPoint(inst);
    auto size = toFreeList.size();
    for (auto i = 0; i < toFreeList.size(); i += 6) {
      switch ((size - i) % 6) {
        case 1:
          builder.CreateCall(invalidateFn, { toFreeList[i] });
          break;
        case 2:
          builder.CreateCall(invalidateFn2, { toFreeList[i], toFreeList[i+1] });
          break;
        case 3:
          builder.CreateCall(invalidateFn3, { toFreeList[i], toFreeList[i+1], toFreeList[i+2] });
          break;
        case 4:
          builder.CreateCall(invalidateFn4, { toFreeList[i], toFreeList[i+1], toFreeList[i+2], toFreeList[i+3] });
          break;
        case 5:
          builder.CreateCall(invalidateFn5, { toFreeList[i], toFreeList[i+1], toFreeList[i+2], toFreeList[i+3], toFreeList[i+4] });
          break;
        // 6
        case 0:
          builder.CreateCall(invalidateFn6, { toFreeList[i], toFreeList[i+1], toFreeList[i+2], toFreeList[i+3], toFreeList[i+4], toFreeList[i+5] });
          break;
      }
    }
  };

  // Stack grows down, so first allocation is high, last is low
  // Hmm.. compiler seems to be reordering the allocas in ways 
  // that break this assumption
  // auto low = allocaList.back();
  // auto high = allocaList.front();
  for (auto &BB: *F) {
    for (auto &instr: BB) {
      if (auto *inst = dyn_cast<ReturnInst>(&instr)) {
        invalidate_all_at(inst);
      }
    }
  }
}

void instrumentMalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);
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
    Value *arg = Inst->getArgOperand(0);
    CallInst *resolveMallocCall = builder.CreateCall(getResolveMalloc(M), { arg });
    Inst->replaceAllUsesWith(resolveMallocCall);
    Inst->eraseFromParent();  
  }
  // TODO: instrument free and other libc allocations
}

void instrumentRealloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

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
    Value *ptr_arg =Inst->getArgOperand(0);
    Value *size_arg = Inst->getArgOperand(1);
    CallInst *resolveReallocCall = builder.CreateCall(getResolveRealloc(M), { ptr_arg, size_arg });
    Inst->replaceAllUsesWith(resolveReallocCall);
    Inst->eraseFromParent();
  }
}

void instrumentCalloc(Function *F) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  auto size_ty = Type::getInt64Ty(Ctx);

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
    Value *num_arg = Inst->getArgOperand(0);
    Value *size_arg = Inst->getArgOperand(1);
    CallInst *resolveCallocCall = builder.CreateCall(getResolveCalloc(M), { num_arg, size_arg });
    Inst->replaceAllUsesWith(resolveCallocCall);
    Inst->eraseFromParent();
  }
}

void instrumentGEP(Function *F, Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  std::unordered_set<GetElementPtrInst *> visitedGep;

  auto resolveGepFn = getOrCreateResolveGepSanitizer(M, Ctx, strategy);

  auto handle_gep = [&](auto* gep) {

    if (visitedGep.contains(gep)) {
      return;
    }

    Value* basePtr = gep->getPointerOperand();
    GetElementPtrInst* derivedPtr = gep;
    gep->setIsInBounds(false);

    // If we are chaining geps we don't need to check each individually, only the total range in the end.
    while (derivedPtr->hasOneUser()) {
      if (auto* gep2 = dyn_cast<GetElementPtrInst>(derivedPtr->user_back())) {
        gep2->setIsInBounds(false);
        visitedGep.insert(gep2);
        derivedPtr = gep2;
      } else {
        break;
      }
    }

    SmallVector<User*, 8> gep_users;
    for (User *U : derivedPtr->users()) {
      gep_users.push_back(U);
    }

    builder.SetInsertPoint(derivedPtr->getNextNode());
    auto resolveGepCall = builder.CreateCall(resolveGepFn, { basePtr, derivedPtr, ConstantExpr::getSizeOf(derivedPtr->getResultElementType()) });

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
    for (auto &inst: BB) {
      if (auto *gep = dyn_cast<GetElementPtrInst>(&inst)) {
        handle_gep(gep);
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

  Module* M = F->getParent();

  auto handleLoadStore = [&](auto* inst) {
    builder.SetInsertPoint(inst);
    auto ptr = inst->getPointerOperand();
    Type* value_ty;
    constexpr bool is_store = std::is_same_v<decltype(inst), StoreInst*>;
    if constexpr (is_store) {
      value_ty = inst->getValueOperand()->getType();
    } else {
      value_ty = inst->getType();
    }

    // Skip trivially correct accesses to stack values in this function (i.e., most automatic variables)
    // Skip if ptr is an alloca and types are the same
    if (auto *alloca = dyn_cast<AllocaInst>(ptr)) {
      if (alloca->getAllocatedType() == value_ty) { return; }
    }

    // If we already checked with `resolve_gep` the pointer will be valid.
    if (auto *call = dyn_cast<CallInst>(ptr)) {
      auto called = call->getCalledFunction();
      if (called && called->getName() == "resolve_gep_sanitized") { return; }
    }

    if constexpr (is_store) {
      auto storeFn = getOrCreateBoundsCheckStoreSanitizer(
        F->getParent(), Ctx, value_ty, strategy
      );

      auto sanitizedStore = builder.CreateCall(storeFn, { ptr, inst->getValueOperand() });
    } else {
      auto loadFn = getOrCreateBoundsCheckLoadSanitizer(F->getParent(),
                                                        Ctx, value_ty, strategy);

      auto sanitizedLoad = builder.CreateCall(loadFn, { ptr });
      inst->replaceAllUsesWith(sanitizedLoad);
    }

    inst->removeFromParent();
    inst->deleteValue();
  };

  for (auto &BB : *F) {
    for (auto &I : BB) {
      if (auto *load = dyn_cast<LoadInst>(&I)) {
        handleLoadStore(load);
      } else if (auto *store = dyn_cast<StoreInst>(&I)) {
        handleLoadStore(store);
      }
    }
  }
}

void sanitizeMemInstBounds(Function *F, Vulnerability::RemediationStrategies strategy) {
  instrumentGEP(F, strategy);
  sanitizeMemcpy(F, strategy);
  sanitizeLoadStore(F, strategy);
}
