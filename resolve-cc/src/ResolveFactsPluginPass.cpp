/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "resolve_facts_llvm/resolve_facts_llvm.hpp"

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

struct ResolveFactsPluginPass : public PassInfoMixin<ResolveFactsPluginPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMFacts facts;
    resolve::getModuleFacts(facts, M);
    auto bytes = facts.serialize();
    resolve::embedFacts(M, bytes.bytes());
    return PreservedAnalyses::all();
  }
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ResolveFactsPluginPass",
          LLVM_VERSION_STRING, [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [&](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(ResolveFactsPluginPass());
                });
          }};
}
