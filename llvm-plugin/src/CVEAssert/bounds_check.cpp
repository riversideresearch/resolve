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


static Function *getOrCreateBoundsCheckMemcpySanitizer(Module *M) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  // void *resolve_memcpy(void *, void *, int64) <-- can fix this as necessary
  FunctionType *SanitizeMemcpyFuncType = FunctionType::get(
      ptr_ty, {ptr_ty, ptr_ty, ptr_ty, ptr_ty, size_ty}, false);

  // Insert libresolve runtime callee definition
  FunctionType *ResolveCheckBoundsFuncType =
      FunctionType::get(Type::getInt1Ty(Ctx), {ptr_ty, ptr_ty, size_ty}, false);
  FunctionCallee ResolveCheckBoundsFunc = M->getOrInsertFunction(
      "resolve_check_bounds", ResolveCheckBoundsFuncType);

  Function *SanitizeMemcpyFunc =
      Function::Create(SanitizeMemcpyFuncType, Function::InternalLinkage,
                       "resolve_sanitize_memcpy", M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", SanitizeMemcpyFunc);
  BasicBlock *RemedBB =
      BasicBlock::Create(Ctx, "sanitize_memcpy", SanitizeMemcpyFunc);
  BasicBlock *ContExecBB =
      BasicBlock::Create(Ctx, "normal_exe", SanitizeMemcpyFunc);

  // EntryBB: Call libresolve check_bounds runtime function
  builder.SetInsertPoint(EntryBB);

  // Extract dst, src, size arguments from function
  Value *dst_ptr = SanitizeMemcpyFunc->getArg(0);
  Value *root_dst = SanitizeMemcpyFunc->getArg(1);
  Value *src_ptr = SanitizeMemcpyFunc->getArg(2);
  Value *root_src = SanitizeMemcpyFunc->getArg(3);
  Value *size_arg = SanitizeMemcpyFunc->getArg(4);

  Value *check_src_bd =
      builder.CreateCall(ResolveCheckBoundsFunc, {root_src, src_ptr, size_arg});
  Value *check_dst_bd =
      builder.CreateCall(ResolveCheckBoundsFunc, {root_dst, dst_ptr, size_arg});

  Value *withinBounds = builder.CreateAnd(check_src_bd, check_dst_bd);
  builder.CreateCondBr(withinBounds, ContExecBB, RemedBB);

  // ContExecBB: Make a call to libc memcpy and return the pointer
  builder.SetInsertPoint(ContExecBB);
  FunctionCallee memcpy_func = M->getOrInsertFunction(
      "memcpy", FunctionType::get(ptr_ty, {ptr_ty, ptr_ty, size_ty}, false));
  Value *memcpy_ptr =
      builder.CreateCall(memcpy_func, {dst_ptr, src_ptr, size_arg});
  builder.CreateRet(memcpy_ptr);

  // RemedBB: Remediated path returns null pointer.
  builder.SetInsertPoint(RemedBB);
  builder.CreateRet(ConstantPointerNull::get(ptr_ty));

  // DEBUGGING
  raw_ostream &out = errs();
  out << *SanitizeMemcpyFunc;
  if (verifyFunction(*SanitizeMemcpyFunc, &out)) {
  }
  return SanitizeMemcpyFunc;
}

static Value *findPtrBase(Function *F, Value *V, MemorySSA &MSSA,
                          MemorySSAWalker *Walker) {
  // Follow Def Use Chains through provenance preserving operations
  // GetElementPtrInst, PHINodes, MemoryDefUse
  std::vector<Value *> roots;
  Worklist<Value *> wl{V};

  auto FollowMemoryDef = [&](Instruction *I) {
    assert(I != nullptr);
    if (FIND_PTR_ROOT_DEBUG)
      errs() << "[CVEAssert] [Find Roots] Following Mem Def " << *I << "\n";

    if (auto Inst = dyn_cast<StoreInst>(I)) {
      wl.push_unique(Inst->getValueOperand());
      return true;
    } else {
      errs() << "[CVEAssert] Error: Unexpected Memory Def Instruction " << *I
             << "\n";
      errs() << "[CVEAssert]    ... when finding roots for " << *V << "\n";
      return false;
    }
  };

  auto FollowMemoryUse = [&](Instruction *I) {
    if (FIND_PTR_ROOT_DEBUG)
      errs() << "[CVEAssert] [Find Roots] Following Mem Use " << *I << "\n";

    // Check if this is a known memory use in MSSA
    if (!I->mayReadFromMemory())
      return false;
    // TODO: When does this condition not hold
    if (!MSSA.getMemoryAccess(I))
      return false;

    auto *Clob = Walker->getClobberingMemoryAccess(I);
    bool found_suitible_def = false;

    if (auto Def = dyn_cast<MemoryDef>(Clob)) {
      found_suitible_def = FollowMemoryDef(Def->getMemoryInst());
    } else if (auto Phi = dyn_cast<MemoryPhi>(Clob)) {
      // TODO Handle loops? Can we ignore blocks that are not dominating
      for (auto &Op : Phi->incoming_values()) {
        if (auto Def = dyn_cast<MemoryDef>(Op)) {
          found_suitible_def |= FollowMemoryDef(Def->getMemoryInst());
        } else {
          llvm_unreachable("There should be no other options.");
        }
      }
    } else {
      llvm_unreachable("There should be no other options.");
    }
    return found_suitible_def;
  };

  while (!wl.empty()) {
    auto top = wl.pop();
    if (FIND_PTR_ROOT_DEBUG)
      errs() << "[CVEAssert] [Find Roots] Tracing " << *top << "\n";
    // Handle operations on pointers
    if (auto Inst = dyn_cast<GetElementPtrInst>(top)) {
      wl.push_unique(Inst->getPointerOperand());

      // Handle PHI Nodes
    } else if (auto Inst = dyn_cast<PHINode>(top)) {
      // TODO Handle loops? Can we ignore blocks that are not dominating
      wl.push_unique_range(Inst->incoming_values().begin(),
                           Inst->incoming_values().end());

    } else if (auto Inst = dyn_cast<CallInst>(top)) {
      roots.push_back(top);
      // Handle pointers loaded from memory
    } else if (auto Inst = dyn_cast<Instruction>(top)) {
      if (!FollowMemoryUse(Inst)) {
        roots.push_back(top);
      }
    } else {
      roots.push_back(top);
    }
  }

  if (roots.size() > 1) {
    errs() << "[CVEAssert] Cannot instrument " << *V << "\n";
    errs() << "[CVEAssert] Multiple Potential allocations: \n";
  } else {
    if (FIND_PTR_ROOT_DEBUG)
      errs() << "[CVEAssert] Found one root for " << *V << "\n";
  }
  for (auto root : roots) {
    if (FIND_PTR_ROOT_DEBUG || roots.size() > 1)
      errs() << "[CVEAssert]   " << *root << "\n";
  }

  return roots.front();
}

void sanitizeLoadStore(Function *F, Vulnerability::RemediationStrategies strategy) 
{
  LLVMContext &Ctx = F->getContext();
  IRBuilder<> builder(Ctx);

  std::vector<LoadInst *> loadList;
  std::vector<StoreInst *> storeList;

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

void sanitizeMemcpy(Function *F, ModuleAnalysisManager &MAM) {
  IRBuilder<> builder(F->getContext());
  // Compute MSSA for this Function
  auto &FAMProxy =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(*F->getParent());
  FunctionAnalysisManager &FAM = FAMProxy.getManager();
  MemorySSA &MSSA = FAM.getResult<MemorySSAAnalysis>(*F).getMSSA();
  MemorySSAWalker *Walker = MSSA.getWalker();

  std::vector<MemCpyInst *> memcpyList;

  for (auto &BB : *F) {
    for (auto &inst : BB) {
      if (auto *memcpyInst = dyn_cast<MemCpyInst>(&inst)) {
        memcpyList.push_back(memcpyInst);
      }
    }
  }

  std::map<Value *, Value *> ptrBase;

  // for (auto Inst : memcpyList) {
  //     auto dst_ptr = Inst->getDest();
  //     auto src_ptr = Inst->getSource();
  //     if (ptrBase.find(dst_ptr) == ptrBase.end()) {
  //         ptrBase[dst_ptr] = findPtrBase(f, dst_ptr, MSSA, Walker);
  //     }

  //     if (ptrBase.find(src_ptr) == ptrBase.end()) {
  //         ptrBase[src_ptr] = findPtrBase(f, src_ptr, MSSA, Walker);
  //     }
  // }

  errs() << "[CVEAssert] Found " << ptrBase.size() << " roots" << "\n";

  for (auto Inst : memcpyList) {
    builder.SetInsertPoint(Inst);
    // getOrCreateBoundsMemcpySanitizer call
    auto dst_ptr = Inst->getDest();
    auto src_ptr = Inst->getSource();
    auto size_arg = Inst->getLength();
    auto memcpyFn = getOrCreateBoundsCheckMemcpySanitizer(F->getParent());

    // FIXME: it would be nice to use find allocation root here
    // auto sanitized_memcpy = builder.CreateCall(memcpyFn, { dst_ptr,
    // ptrBase[dst_ptr], src_ptr, ptrBase[src_ptr], size_arg });
    auto sanitized_memcpy = builder.CreateCall(
        memcpyFn, {dst_ptr, dst_ptr, src_ptr, src_ptr, size_arg});
    Inst->replaceAllUsesWith(sanitized_memcpy);
    Inst->eraseFromParent();
  }
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

void sanitizeMalloc(Function *F, Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  const DataLayout &DL = M->getDataLayout();

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

  FunctionType *resolveGEPFnTy = FunctionType::get(
    ptr_ty,
    { ptr_ty, ptr_ty },
    false
  );

  FunctionCallee resolveGEPFn = M->getOrInsertFunction(
    "resolve_gep",
    resolveGEPFnTy
  );

  std::vector<CallInst *> mallocList;
  std::vector<GetElementPtrInst *> gepList;

  switch(strategy) {
    //case Vulnerability::RemediationStrategies::CONTINUE-WRAP: /* TODO: Not yet supported. Implement this remediaion strategy */
    //case Vulnerability::RemediationStrategies::CONTINUE-ZERO: /* TODO: Not yet supported. Implement this remediation strategy */
    case Vulnerability::RemediationStrategies::EXIT:
    case Vulnerability::RemediationStrategies::RECOVER:
    case Vulnerability::RemediationStrategies::SAT:                     /* TODO: Not yet supported. Implement this remediation strategy */
      break;

    default:
      llvm::errs() << "[CVEAssert] Error: sanitizeMalloc does not support remediation strategy "
                   << "defaulting to EXIT strategy!\n";
      strategy = Vulnerability::RemediationStrategies::EXIT;
      break;
  }


  for (auto &BB : *F) {
    for (auto &inst: BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFunc = call->getCalledFunction();

        if (!calledFunc) { continue; }

        StringRef fnName = calledFunc->getName();
        
        if (fnName == "malloc") { mallocList.push_back(call); }
      } else if (auto *gep = dyn_cast<GetElementPtrInst>(&inst)) {
        gepList.push_back(gep);
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

  for (auto GEPInst: gepList) {
    builder.SetInsertPoint(GEPInst->getNextNode());

    // Get the pointer operand and offset from GEP
    Value *basePtr = GEPInst->getPointerOperand();
    Value * derivedPtr = GEPInst;

    auto resolveGEPCall = builder.CreateCall(resolveGEPFn, { basePtr, derivedPtr });
    // GEPInst->replaceAllUsesWith(resolveGEPCall);
  }

  sanitizeLoadStore(F, strategy);
}

void sanitizeMemInstBounds(Function *F, ModuleAnalysisManager &MAM, Vulnerability::RemediationStrategies strategy) {
  // FIXME: bad alias analysis is causing compilation to fail
  // TBD: why does TBAA not work right
  // sanitizeLoadStore(f, MAM);
  sanitizeAlloca(F);
  sanitizeMalloc(F, strategy);
  // sanitizeMemcpy(f, MAM);
}