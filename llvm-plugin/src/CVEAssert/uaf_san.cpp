/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include "Vulnerability.hpp"
#include "helpers.hpp"

#include <unordered_set>

using namespace llvm;

static std::unordered_set<std::string> instrumentedFns = { "resolve_free" };

static Function *getOrCreateCheckLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy) {
    std::string handlerName = "resolve_check_ld_" + getLLVMType(ty);

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

    // TODO: Create a rtlib function that checks if ptr has been freed

    Value *basePtr = sanitizeLoadFn->getArg(0);
    builder.SetInsertPoint(EntryBB);

    // TODO insert call to rtlib function

    // NormalLoadBB: Dereference the pointer (Read value from memory)
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
    if (verifyFunction(*sanitizeLoadFn, &out)) {}

    return sanitizeLoadFn;
}

static Function *getOrCreateStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy) {
    std::string handlerName = "resolve_check_st_" + getLLVMType(ty);

    if (auto handler = M->getFunction(handlerName)) {
        return handler;
    }

    IRBuilder<> builder(Ctx);

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

     // TODO: Create a rtlib function that checks if ptr has been freed
    Value *basePtr = sanitizeStoreFn->getArg(0);
    Value *storedVal = sanitizeStoreFn->getArg(1);

    builder.SetInsertPoint(EntryBB);

    // NormalStoreBB: Dereference the pointer (Write value to memory)
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
    if (verifyFunction(*sanitizeStoreFn, &out)) {}
    return sanitizeStoreFn;

}

void instrumentFree(Function *F) {
    Module *M = F->getParent();
    LLVMContext &Ctx = M->getContext();
    IRBuilder<> builder(Ctx);

    auto ptr_ty = PointerType::get(Ctx, 0);
    auto void_ty = Type::getVoidTy(Ctx);

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

    for (auto Inst: freeList) {
        StringRef fnName = Inst->getFunction()->getName();

        if (instrumentedFns.find(fnName.str()) != instrumentedFns.end()) {
            continue;
        }

        builder.SetInsertPoint(Inst);
        Value *ptr_arg = Inst->getArgOperand(0);
        CallInst *resolveFreeCall = builder.CreateCall(getOrCreateWeakResolveFree(M), { ptr_arg });
        Inst->replaceAllUsesWith(resolveFreeCall);
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

    auto loadFn = getOrCreateCheckLoadSanitizer(F->getParent(),
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

    auto storeFn = getOrCreateCheckStoreSanitizer(
      F->getParent(), F->getContext(), valueTy, strategy
    );

    auto sanitizedStore = builder.CreateCall(storeFn, { ptr, Inst->getValueOperand() });
    Inst->removeFromParent();
    Inst->deleteValue();
  }
}

void sanitizeUseAfterFree(Function *F, Vulnerability::RemediationStrategies strategy) {
    sanitizeLoadStore(F, strategy);
}