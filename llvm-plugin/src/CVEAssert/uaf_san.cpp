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

static Function *getOrCreateUseAfterFreeSanitizer() {

}

void sanitizeUseAfterFree(Function *F, Vulnerability::RemediationStrategies strategy) {
}