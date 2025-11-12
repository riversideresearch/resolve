/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <vector>

using namespace llvm;

struct DLHook : public PassInfoMixin<DLHook> {
  void runOnFunction(Function &F) {
    std::vector<CallInst *> dlsymCalls;
    Module *M = F.getParent();
    LLVMContext &Ctx = M->getContext();

    FunctionCallee resolveDlsymFunc = M->getOrInsertFunction(
        "resolve_dlsym",
        FunctionType::get(PointerType::get(Ctx, 0),
                          {PointerType::get(Ctx, 0), PointerType::get(Ctx, 0)},
                          false));

    for (auto &BB : F) {
      for (auto &Inst : BB) {
        if (auto *call = dyn_cast<CallInst>(&Inst)) {
          Function *calledFunc = call->getCalledFunction();

          if (!calledFunc) {
            continue;
          }

          StringRef funcName = calledFunc->getName();
          if (funcName == "dlsym") {
            dlsymCalls.push_back(call);
          }
        }
      }
    }

    for (auto call : dlsymCalls) {
      IRBuilder<> Builder(call);

      Value *symbol = call->getArgOperand(0);
      Value *handle = call->getArgOperand(1);

      CallInst *resolveDlsymCall =
          Builder.CreateCall(resolveDlsymFunc, {handle, symbol});
      resolveDlsymCall->setCallingConv(call->getCallingConv());

      call->replaceAllUsesWith(resolveDlsymCall);
      call->eraseFromParent();
    }

    return;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    for (auto &F : M) {
      runOnFunction(F);
    }

    /* IR is modified */
    return PreservedAnalyses::none();
  }
};

/* New PM Registration */
PassPluginLibraryInfo getDLHookInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DlsymHook", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(DLHook());
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getDLHookInfo();
}
