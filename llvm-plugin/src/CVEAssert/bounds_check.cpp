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
#include "helpers.hpp"

static const bool FIND_PTR_ROOT_DEBUG = true;

#include <map>

using namespace llvm;

static Function *
getOrCreateBoundsCheckLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty) {
  Twine handlerName = "resolve_sanitize_bounds_ld_" + getLLVMType(ty);
  SmallVector<char> handlerNameStr;

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> Builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  // Sanitize function creation
  FunctionType *SanitizeLoadFuncType =
      FunctionType::get(ty, {ptr_ty, ptr_ty}, false);
  Function *SanitizeLoadFunc = Function::Create(
      SanitizeLoadFuncType, Function::InternalLinkage, handlerName, M);

  // Basic blocks
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeLoadFunc);
  BasicBlock *SanitizeBlock =
      BasicBlock::Create(Ctx, "sanitize_block", SanitizeLoadFunc);
  BasicBlock *LoadBlock =
      BasicBlock::Create(Ctx, "load_block", SanitizeLoadFunc);
  BasicBlock *CheckDerivedPtrBlock =
      BasicBlock::Create(Ctx, "check_derived_alloc", SanitizeLoadFunc);
  BasicBlock *HeapBlock =
      BasicBlock::Create(Ctx, "heap_alloc_case", SanitizeLoadFunc);
  BasicBlock *StackBlock =
      BasicBlock::Create(Ctx, "stack_alloc_case", SanitizeLoadFunc);
  // Store the arguments of the sanitized load function
  Value *base_ptr = SanitizeLoadFunc->getArg(0);
  Value *derived_ptr = SanitizeLoadFunc->getArg(1);

  Builder.SetInsertPoint(Entry);
  // Checking if the base ptr is a stack allocation
  auto base_ptr_check =
      Builder.CreateCall(getOrCreateIsHeap(M, Ctx), {base_ptr});
  Builder.CreateCondBr(base_ptr_check, HeapBlock, CheckDerivedPtrBlock);

  Builder.SetInsertPoint(CheckDerivedPtrBlock);

  auto derived_ptr_check =
      Builder.CreateCall(getOrCreateIsHeap(M, Ctx), {derived_ptr});
  Value *checkDerivedPtr = Builder.CreateAnd(base_ptr_check, derived_ptr_check);
  Builder.CreateCondBr(checkDerivedPtr, HeapBlock, StackBlock);

  Builder.SetInsertPoint(HeapBlock);
  // Insert libresolve function call
  FunctionType *CheckBoundsFuncType =
      FunctionType::get(Type::getInt1Ty(Ctx), {ptr_ty, ptr_ty, size_ty}, false);
  FunctionCallee BoundsCheckFunc =
      M->getOrInsertFunction("resolve_check_bounds", CheckBoundsFuncType);
  Value *BoundsValue = Builder.CreateCall(
      BoundsCheckFunc, {base_ptr, derived_ptr, ConstantExpr::getSizeOf(ty)});

  // Conditional branch instruction
  Builder.CreateCondBr(BoundsValue, LoadBlock, SanitizeBlock);

  Builder.SetInsertPoint(StackBlock);
  Builder.CreateBr(LoadBlock);

  // Set the arbitatry return value
  Builder.SetInsertPoint(SanitizeBlock);
  FunctionType *LogSanitizeFuncType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
  FunctionCallee LogSanitizeFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", LogSanitizeFuncType);
  Builder.CreateCall(LogSanitizeFunc, {base_ptr});

  Builder.CreateRet(Constant::getNullValue(ty));

  // Return Block: returns pointer if non-null
  Builder.SetInsertPoint(LoadBlock);
  Value *ld = Builder.CreateLoad(ty, derived_ptr);
  Builder.CreateRet(ld);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *SanitizeLoadFunc;
  if (verifyFunction(*SanitizeLoadFunc, &out)) {
  }

  return SanitizeLoadFunc;
}

static Function *
getOrCreateBoundsCheckStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty) {
  Twine handlerName = "resolve_sanitize_bounds_st_" + getLLVMType(ty);
  SmallVector<char> handlerNameStr;

  if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
    return handler;

  IRBuilder<> Builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto size_ty = Type::getInt64Ty(Ctx);

  FunctionType *SanitizeStoreFuncType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty, ptr_ty, ty}, false);
  Function *SanitizeStoreFunc = Function::Create(
      SanitizeStoreFuncType, Function::InternalLinkage, handlerName, M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeStoreFunc);
  BasicBlock *SanitizeBlock =
      BasicBlock::Create(Ctx, "sanitize_block", SanitizeStoreFunc);
  BasicBlock *StoreBlock =
      BasicBlock::Create(Ctx, "store_block", SanitizeStoreFunc);
  BasicBlock *CheckDerivedPtrBlock =
      BasicBlock::Create(Ctx, "check_derived_alloc", SanitizeStoreFunc);
  BasicBlock *HeapBlock =
      BasicBlock::Create(Ctx, "heap_alloc_case", SanitizeStoreFunc);
  BasicBlock *StackBlock =
      BasicBlock::Create(Ctx, "stack_alloc_case", SanitizeStoreFunc);

  Value *base_ptr = SanitizeStoreFunc->getArg(0);
  Value *derived_ptr = SanitizeStoreFunc->getArg(1);

  Builder.SetInsertPoint(Entry);
  // Checking if the base ptr is a stack allocation
  auto base_ptr_check =
      Builder.CreateCall(getOrCreateIsHeap(M, Ctx), {base_ptr});
  Builder.CreateCondBr(base_ptr_check, HeapBlock, CheckDerivedPtrBlock);

  Builder.SetInsertPoint(CheckDerivedPtrBlock);

  auto derived_ptr_check =
      Builder.CreateCall(getOrCreateIsHeap(M, Ctx), {derived_ptr});
  Value *checkDerivedPtr = Builder.CreateAnd(base_ptr_check, derived_ptr_check);
  Builder.CreateCondBr(checkDerivedPtr, HeapBlock, StackBlock);

  Builder.SetInsertPoint(HeapBlock);
  // Insert libresolve function call
  FunctionType *CheckBoundsFuncType =
      FunctionType::get(Type::getInt1Ty(Ctx), {ptr_ty, ptr_ty, size_ty}, false);
  FunctionCallee BoundsCheckFunc =
      M->getOrInsertFunction("resolve_check_bounds", CheckBoundsFuncType);
  Value *BoundsValue = Builder.CreateCall(
      BoundsCheckFunc, {base_ptr, derived_ptr, ConstantExpr::getSizeOf(ty)});

  // Conditional branch instruction
  Builder.CreateCondBr(BoundsValue, StoreBlock, SanitizeBlock);

  Builder.SetInsertPoint(StackBlock);
  Builder.CreateBr(StoreBlock);

  Builder.SetInsertPoint(SanitizeBlock);
  FunctionType *LogSanitizeFuncType =
      FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
  FunctionCallee LogSanitizeFunc = M->getOrInsertFunction(
      "resolve_report_sanitize_mem_inst_triggered", LogSanitizeFuncType);
  Builder.CreateCall(LogSanitizeFunc, {base_ptr});
  Builder.CreateRetVoid();

  Builder.SetInsertPoint(StoreBlock);
  Value *storeValue = SanitizeStoreFunc->getArg(2);
  Builder.CreateStore(storeValue, derived_ptr);
  Builder.CreateRetVoid();

  // DEBUGGING
  raw_ostream &out = errs();
  out << *SanitizeStoreFunc;
  if (verifyFunction(*SanitizeStoreFunc, &out)) {
  }

  return SanitizeStoreFunc;
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

void sanitizeLoadStore(Function *f, ModuleAnalysisManager &MAM) {
  IRBuilder<> builder(f->getContext());
  // Compute MSSA for this Function
  auto &FAMProxy =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(*f->getParent());
  FunctionAnalysisManager &FAM = FAMProxy.getManager();
  MemorySSA &MSSA = FAM.getResult<MemorySSAAnalysis>(*f).getMSSA();
  MSSA.ensureOptimizedUses();
  if (FIND_PTR_ROOT_DEBUG)
    MemorySSAPrinterPass(errs(), true).run(*f, FAM);
  MemorySSAWalker *Walker = MSSA.getWalker();

  std::vector<LoadInst *> loadList;
  std::vector<StoreInst *> storeList;

  for (auto &BB : *f) {
    for (auto &I : BB) {
      if (auto Inst = dyn_cast<LoadInst>(&I)) {
        loadList.push_back(Inst);
      } else if (auto Inst = dyn_cast<StoreInst>(&I)) {
        storeList.push_back(Inst);
      }
    }
  }

  // This object maps Load/Store ptr arguments to their "base"
  // TBD: Define "base"
  // The base ptr is defined as the original ptr allocation
  // which is passed to load or store instruction as an argument
  // For example with a stack-based object:
  //
  // %base = alloca [3 * i32]
  // ...
  // %mem_access = getelementptr [3 * i32], ptr %base, i64 0, i64 0
  // %result = call i32 @resolve_sanitize_bounds_ld_i32(ptr %base, %ptr
  // mem_access)

  std::map<Value *, Value *> ptrBase;

  for (auto Inst : loadList) {
    auto ptr = Inst->getPointerOperand();
    if (ptrBase.find(ptr) == ptrBase.end()) {
      ptrBase[ptr] = findPtrBase(f, ptr, MSSA, Walker);
    }
  }
  for (auto Inst : storeList) {
    auto ptr = Inst->getPointerOperand();
    if (ptrBase.find(ptr) == ptrBase.end()) {
      ptrBase[ptr] = findPtrBase(f, ptr, MSSA, Walker);
    }
  }

  errs() << "[CVEAssert] Found " << ptrBase.size() << " roots" << "\n";

  for (auto Inst : loadList) {
    builder.SetInsertPoint(Inst);
    // getOrCreateBoundsSanitizerLoad call
    auto ptr = Inst->getPointerOperand();
    auto valueTy = Inst->getType();
    if (getLLVMType(valueTy) == "") {
      errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy
             << "\n";
      continue;
    }

    auto loadFn = getOrCreateBoundsCheckLoadSanitizer(f->getParent(),
                                                      f->getContext(), valueTy);
    // Nothing to sanitize
    if (ptr == ptrBase[ptr])
      continue;

    auto sanitized_load = builder.CreateCall(loadFn, {ptrBase[ptr], ptr});
    Inst->replaceAllUsesWith(sanitized_load);
    Inst->removeFromParent();
    Inst->deleteValue();
  }

  for (auto Inst : storeList) {
    builder.SetInsertPoint(Inst);
    // getOrCreateBoundsSanitizerStore call
    auto ptr = Inst->getPointerOperand();
    auto valueTy = Inst->getValueOperand()->getType();
    if (getLLVMType(valueTy) == "") {
      errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy
             << "\n";
      continue;
    }
    auto storeFn = getOrCreateBoundsCheckStoreSanitizer(
        f->getParent(), f->getContext(), valueTy);
    // Nothing to sanitize
    if (ptr == ptrBase[ptr])
      continue;

    auto sanitized_store = builder.CreateCall(
        storeFn, {ptrBase[ptr], ptr, Inst->getValueOperand()});
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeMemcpy(Function *f, ModuleAnalysisManager &MAM) {
  IRBuilder<> builder(f->getContext());
  // Compute MSSA for this Function
  auto &FAMProxy =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(*f->getParent());
  FunctionAnalysisManager &FAM = FAMProxy.getManager();
  MemorySSA &MSSA = FAM.getResult<MemorySSAAnalysis>(*f).getMSSA();
  MemorySSAWalker *Walker = MSSA.getWalker();

  std::vector<MemCpyInst *> memcpyList;

  for (auto &BB : *f) {
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
    auto memcpyFn = getOrCreateBoundsCheckMemcpySanitizer(f->getParent());

    // FIXME: it would be nice to use find allocation root here
    // auto sanitized_memcpy = builder.CreateCall(memcpyFn, { dst_ptr,
    // ptrBase[dst_ptr], src_ptr, ptrBase[src_ptr], size_arg });
    auto sanitized_memcpy = builder.CreateCall(
        memcpyFn, {dst_ptr, dst_ptr, src_ptr, src_ptr, size_arg});
    Inst->replaceAllUsesWith(sanitized_memcpy);
    Inst->eraseFromParent();
  }
}

void sanitizeMemInstBounds(Function *f, ModuleAnalysisManager &MAM) {
  // FIXME: bad alias analysis is causing compilation to fail
  // TBD: why does TBAA not work right
  sanitizeLoadStore(f, MAM);
  sanitizeMemcpy(f, MAM);
}