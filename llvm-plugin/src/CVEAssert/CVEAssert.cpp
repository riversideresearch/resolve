#include "llvm/Analysis/MemorySSA.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "CVEAssert.hpp"
#include "Vulnerability.hpp"
#include "Worklist.hpp"

#include "arith_san.hpp"
#include "bounds_check.hpp"
#include "helpers.hpp"
#include "null_ptr.hpp"

using namespace llvm;

// Global env vars
bool CVE_ASSERT_DEBUG;
const char *CVE_ASSERT_STRATEGY;

namespace {

struct LabelCVEPass : public PassInfoMixin<LabelCVEPass> {
  std::vector<Vulnerability> vulnerabilities;

  LabelCVEPass() {
    // Initialize env vars
    CVE_ASSERT_STRATEGY = strdup(std::getenv("RESOLVE_STRATEGY") ?: "");
    CVE_ASSERT_DEBUG = strlen(std::getenv("CVE_ASSERT_DEBUG") ?: "") > 0;

    vulnerabilities = Vulnerability::parseVulnerabilityFile();
  }

  Function *getOrCreateFreeOfNonHeapSanitizer(Module *M, LLVMContext &Ctx) {
    std::string handlerName = "resolve_sanitize_non_heap_free";

    if (auto handler = M->getFunction(handlerName))
      return handler;

    IRBuilder<> Builder(Ctx);
    // TODO: handle address spaces other than 0
    auto ptr_ty = PointerType::get(Ctx, 0);

    // TODO: write this in asm as some kind of sanitzer_rt?
    FunctionType *FuncType =
        FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
    Function *SanitizeFunc =
        Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeFunc);
    BasicBlock *SanitizeBlock =
        BasicBlock::Create(Ctx, "sanitize_block", SanitizeFunc);
    BasicBlock *FreeBlock = BasicBlock::Create(Ctx, "free_block", SanitizeFunc);

    // Set insertion point to entry block
    Builder.SetInsertPoint(Entry);

    // Get function argument
    Argument *InputPtr = SanitizeFunc->getArg(0);

    // Call Is Heap Func
    // Branch if True
    Function *isHeapFunc = getOrCreateIsHeap(M, Ctx);
    Value *IsHeap = Builder.CreateCall(isHeapFunc, {InputPtr});

    // Conditional branch
    Builder.CreateCondBr(IsHeap, FreeBlock, SanitizeBlock);

    // Sanitize Block: do Nothing
    Builder.SetInsertPoint(SanitizeBlock);
    Builder.CreateRetVoid();

    // Free Block: call Free
    Builder.SetInsertPoint(FreeBlock);
    Builder.CreateCall(M->getFunction("free"), {InputPtr});
    Builder.CreateRetVoid();

    raw_ostream &out = errs();
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {
    }

    return SanitizeFunc;
  }

  void sanitizeFreeOfNonHeap(Function *f) {
    IRBuilder<> builder(f->getContext());
    std::vector<CallInst *> workList;

    for (auto &BB : *f) {
      for (auto &I : BB) {
        if (auto Inst = dyn_cast<CallInst>(&I)) {
          if (auto Callee = Inst->getCalledFunction())
            if (Callee->getName() == "free") {
              workList.push_back(Inst);
            }
        }
      }
    }

    for (auto Call : workList) {
      builder.SetInsertPoint(Call);
      auto sanitizerFn =
          getOrCreateFreeOfNonHeapSanitizer(f->getParent(), f->getContext());

      auto sanitizedFree =
          builder.CreateCall(sanitizerFn, {Call->getArgOperand(0)});
      Call->removeFromParent();
      Call->deleteValue();
    }
  }

  /// For each function, if it matches the target function name, insert calls to
  /// the vulnerability handlers as specified in the JSON. Each call receives
  /// the triggering argument parsed from the JSON.
  PreservedAnalyses run(Function &F, ModuleAnalysisManager &MAM,
                        Vulnerability &vuln) {
    char *demangledNamePtr = llvm::itaniumDemangle(F.getName().str(), false);
    std::string demangledName(demangledNamePtr ?: "");

    if (CVE_ASSERT_DEBUG) {
      errs() << "[CVEAssert] Trying fn " << F.getName()
             << " Demangled name: " << demangledName << "\n";
    }

    raw_ostream &out = errs();

    if (vuln.TargetFunctionName.empty() ||
        (demangledName.find(vuln.TargetFunctionName) == std::string::npos &&
         F.getName().str().find(vuln.TargetFunctionName) ==
             std::string::npos)) {
      return PreservedAnalyses::all();
    }

    out << "[CVEAssert] === Pre Instrumented IR === \n";
    out << F;

    if (vuln.WeaknessID == 476) {
      // instrumentNullPtr(M, Ctx, &F);
      sanitizeNullPointers(&F);
    } else if (vuln.WeaknessID == 590) {
      sanitizeFreeOfNonHeap(&F);
    } else if (vuln.WeaknessID == 133) {
      sanitizeMemInstBounds(&F, MAM);
    } else if (vuln.WeaknessID == 132) {
      sanitizeMemInstBounds(&F, MAM);
    } else if (vuln.WeaknessID == 369) {
      sanitizeDivideByZero(&F);
      sanitizeDivideByZeroinFunction(&F, vuln.UndesirableFunction);
    } else {
      errs() << "[CVEAssert] Error: CWE " << vuln.WeaknessID
             << "not implemented\n";
    }

    out << "[CVEAssert] === Post Instrumented IR === \n";
    out << F;

    if (verifyFunction(F, &out)) {
      report_fatal_error("[CVEAssert] We broke something");
    }

    errs() << "[CVEAssert] Inserted vulnerability handler calls in function "
           << vuln.TargetFileName << ":" << vuln.TargetFunctionName << "\n";
    return PreservedAnalyses::none();
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    auto result = PreservedAnalyses::all();
    for (auto &F : M) {
      for (auto &vuln : vulnerabilities) {
        result.intersect(run(F, MAM, vuln));
      }
    }
    return PreservedAnalyses::all();
  }
};

} // end anonymous namespace

// New Pass Manager registration.
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LabelCVE", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(LabelCVEPass());
                  return true;
                });
          }};
}
