#include "llvm/Analysis/MemorySSA.h"
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
#include "llvm/Demangle/Demangle.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <optional>

#include "CVEAssert.hpp"
#include "Worklist.hpp"
#include "Vulnerability.hpp"

#include "helpers.hpp"
#include "null_ptr.hpp"
#include "arith_san.hpp"
#include "bounds_check.hpp"

using namespace llvm;

// Global env vars
bool CVE_ASSERT_DEBUG;
const char *CVE_ASSERT_STRATEGY;

namespace {

struct LabelCVEPass : public PassInfoMixin<LabelCVEPass> {
  std::vector<Vulnerability> vulnerabilities;
  
  enum VulnID {
    OOB_READ = 125,                /* NOTE: This ID corresponds to CWE-ID description found in stb-resize, lamartine CPs */
    INCORRECT_BUF_SIZE = 131,      /* NOTE: This ID corresponds to the CWE-ID description found in analyze image CP*/
    DIVIDE_BY_ZERO = 369,          /* NOTE: This ID corresponds to CWE description in ros2 challenge problem */
    INT_OVERFLOW = 455,            /* NOTE: This ID does not have a corresponding CWE description in a CP, this was to test the integer overflow sanitizer */
    NULL_PTR_DEREF = 476,          /* NOTE: This ID has been found in OpenALPR, NASA CFS, stb-convert CPs */
    STACK_FREE = 590               /* NOTE: This ID has been found in NASA CFS challenge problem */
  };
  
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
      FunctionType *FuncType = FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
      Function *SanitizeFunc = Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

      BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeFunc);
      BasicBlock *SanitizeBlock = BasicBlock::Create(Ctx, "sanitize_block", SanitizeFunc);
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
      if (verifyFunction(*SanitizeFunc, &out)) {}

      return SanitizeFunc;
  }

  void sanitizeFreeOfNonHeap(Function *f) {
    IRBuilder<> builder(f->getContext());
    std::vector<CallInst*> workList;

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
      auto sanitizerFn = getOrCreateFreeOfNonHeapSanitizer(f->getParent(), f->getContext());

      auto sanitizedFree = builder.CreateCall(sanitizerFn, {Call->getArgOperand(0)});
      Call->removeFromParent();
      Call->deleteValue();
    }
  }
  
/// For each function, if it matches the target function name, insert calls to
/// the vulnerability handlers as specified in the JSON. Each call receives the
/// triggering argument parsed from the JSON.
  PreservedAnalyses run(Function &F, ModuleAnalysisManager &MAM, Vulnerability &vuln) {
    char* demangledNamePtr = llvm::itaniumDemangle(F.getName().str(), false);
    std::string demangledName(demangledNamePtr ?: "");

    if (CVE_ASSERT_DEBUG) {
      errs() << "[CVEAssert] Trying fn " << F.getName() << " Demangled name: " << demangledName << "\n";
    }

    raw_ostream &out = errs();

    if (vuln.TargetFunctionName.empty() ||
      (demangledName.find(vuln.TargetFunctionName) == std::string::npos && 
        F.getName().str().find(vuln.TargetFunctionName) == std::string::npos)) {
      return PreservedAnalyses::all();
    }

    out << "[CVEAssert] === Pre Instrumented IR === \n";
    out << F;

    switch (vuln.WeaknessID) {
      case VulnID::OOB_READ:           /* NOTE: Found in stb-resize, lamartine challenge problems */
      case VulnID::INCORRECT_BUF_SIZE: /* NOTE: These IDs correspond to CWEs found in analyze-image */
        sanitizeMemInstBounds(&F, MAM);
        break;

      case VulnID::DIVIDE_BY_ZERO: /* NOTE: This ID corresponds to CWE description in ros2 challenge problem */
        if (vuln.UndesirableFunction.has_value()) {
          sanitizeDivideByZeroInFunction(&F, vuln.UndesirableFunction);
        } else {
          sanitizeDivideByZero(&F);
        }
        break;

      case VulnID::INT_OVERFLOW: /* NOTE: This ID has not been found in any challenge problem,
                                   implemented to for arithmetic sanitizer coverage   */
        sanitizeIntOverflow(&F);
        break;

      case VulnID::NULL_PTR_DEREF: /* NOTE: This ID has been found in OpenALPR, NASA CFS, stb-convert challenge problems */
        sanitizeNullPointers(&F);
        break;

      case VulnID::STACK_FREE: /* NOTE: This ID has been found in NASA CFS challenge problem */
        sanitizeFreeOfNonHeap(&F);
        break;

      default:
        errs() << "[CVEAssert] Error: CWE " << vuln.WeaknessID
                << " not implemented\n";
    }

    out << "[CVEAssert] === Post Instrumented IR === \n"; 
    out << F;

    if (verifyFunction(F, &out)) {
      report_fatal_error("[CVEAssert] We broke something");
    }

    errs() << "[CVEAssert] Inserted vulnerability handler calls in function " << vuln.TargetFileName << ":" << vuln.TargetFunctionName << "\n";
    return PreservedAnalyses::none();
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    auto result = PreservedAnalyses::all();
    for (auto &F: M) {
      for (auto &vuln : vulnerabilities) {
        result.intersect(run(F, MAM, vuln));
      }
    }
    return PreservedAnalyses::all();
  }
};

} // end anonymous namespace

// New Pass Manager registration.
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "LabelCVE", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel) {
          MPM.addPass(LabelCVEPass());
          return true;
        });
    }
  };
}
