/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

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
#include "undesirableop.hpp"

using namespace llvm;

// Global env var
bool CVE_ASSERT_DEBUG;

namespace {

struct InstrumentMemInst {
  bool instrumentMalloc = false;
  bool instrmentRealloc = false;
  bool instrumentAlloca = false;
};

struct LabelCVEPass : public PassInfoMixin<LabelCVEPass> {
  std::vector<Vulnerability> vulnerabilities;
  
  enum VulnID {
    STACK_BASED_BUF_OVERFLOW = 121,
    HEAP_BASED_BUF_OVERFLOW = 122,
    WRITE_WHAT_WHERE = 123,        
    OOB_WRITE = 787,
    OOB_READ = 125,                /* NOTE: This ID corresponds to CWE-ID description found in stb-resize, lamartine CPs */
    INCORRECT_BUF_SIZE = 131,      /* NOTE: This ID corresponds to the CWE-ID description found in analyze image CP*/
    DIVIDE_BY_ZERO = 369,          /* NOTE: This ID corresponds to CWE description in ros2 challenge problem */
    INT_OVERFLOW = 190,            /* NOTE: This ID corresponds to CWE-ID description in redis  */
    NULL_PTR_DEREF = 476,          /* NOTE: This ID has been found in OpenALPR, NASA CFS, stb-convert CPs */
    STACK_FREE = 590               /* NOTE: This ID has been found in NASA CFS challenge problem */
  };
  
  LabelCVEPass() {
    // Initialize env var    
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

  void sanitizeFreeOfNonHeap(Function *f, Vulnerability::RemediationStrategies strategy) {
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
  PreservedAnalyses runOnFunction(Function &F, ModuleAnalysisManager &MAM, Vulnerability &vuln) {
    char* demangledNamePtr = llvm::itaniumDemangle(F.getName().str(), false);
    std::string demangledName(demangledNamePtr ?: "");
    auto result = PreservedAnalyses::all();

    if (CVE_ASSERT_DEBUG) {
      errs() << "[CVEAssert] Trying fn " << F.getName() << " Demangled name: " << demangledName << "\n";
    }

    raw_ostream &out = errs();

    if (vuln.TargetFunctionName.empty() ||
      (demangledName.find(vuln.TargetFunctionName) == std::string::npos && 
      F.getName().str().find(vuln.TargetFunctionName) == std::string::npos)) {
      return result;
    }

    out << "[CVEAssert] === Pre Instrumented IR === \n";
    out << F;

    if (vuln.UndesirableFunction.has_value()) {
      /* NOTE: We are using '0' as a temporary this will be updated future PRs */
      sanitizeUndesirableOperationInFunction(&F, *vuln.UndesirableFunction, 0);
      result = PreservedAnalyses::none();
      out << "[CVEAssert] === Post Sanitization of Undesirable Operation IR === \n"; 
      out << F;
    }

    if (vuln.Strategy == Vulnerability::RemediationStrategies::NONE) {
      errs() << "[CVEAssert] NONE strategy selected for " << vuln.TargetFileName << ":" << vuln.TargetFunctionName << "...\n";
      errs() << "[CVEAssert] Skipping remediation\n";
      return result;
    }

    switch (vuln.WeaknessID) {
      case VulnID::STACK_BASED_BUF_OVERFLOW: /* Stack-based buffer overflow */
      case VulnID::HEAP_BASED_BUF_OVERFLOW: /* Heap-base buffer overflow */
      case VulnID::OOB_WRITE:               /* OOB Write */
      case VulnID::WRITE_WHAT_WHERE:
        sanitizeMemInstBounds(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
        break;

      
      case VulnID::OOB_READ:             /* OOB Read; found in stb-resize, lamartine challenge problems */
      case VulnID::INCORRECT_BUF_SIZE:   /* Incorrect buffer size calculation; found in analyze-image */
        sanitizeMemInstBounds(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
        break;

      case VulnID::DIVIDE_BY_ZERO: /* Divide by Zero; found in ros2 and analyze-image */
        /* Workaround for ambiguous CWE description in analyze-image */
        sanitizeDivideByZero(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
        break;

      case VulnID::INT_OVERFLOW: /* Integer Overflow */
        sanitizeIntOverflow(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
        break;

      case VulnID::NULL_PTR_DEREF: /* Null Pointer Dereference; Found in openalpr, nasa-cfs, stb-convert*/
        sanitizeNullPointers(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
        break;

      case VulnID::STACK_FREE: /* Stack free;  Found in nasa-cfs */
        sanitizeFreeOfNonHeap(&F, vuln.Strategy);
        result = PreservedAnalyses::none();
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
    return result;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    auto result = PreservedAnalyses::all();
    InstrumentMemInst instrument_mem_inst;

    for (auto &vuln : vulnerabilities) {
      // Also skip instrumentation for skipped vulnerabilities
      if (vuln.Strategy == Vulnerability::RemediationStrategies::NONE) {
        continue;
      }

      switch(vuln.WeaknessID) {
        // 121 stack-based
        case VulnID::STACK_BASED_BUF_OVERFLOW:
          instrument_mem_inst.instrumentAlloca = true;
          break;

        // 122 heap-based 
        case VulnID::HEAP_BASED_BUF_OVERFLOW:
          instrument_mem_inst.instrumentMalloc = true;
          instrument_mem_inst.instrmentRealloc = true;
          break;

        // default instrument both
        case VulnID::OOB_READ:
        case VulnID::OOB_WRITE:
        case VulnID::INCORRECT_BUF_SIZE:
        case VulnID::WRITE_WHAT_WHERE:
          instrument_mem_inst.instrumentAlloca = true;
          instrument_mem_inst.instrumentMalloc = true;
          instrument_mem_inst.instrmentRealloc = true;
          break;
        
      }
    }

    for (auto &F : M) {
      if (instrument_mem_inst.instrumentAlloca) {
        instrumentAlloca(&F);
      }

      if (instrument_mem_inst.instrumentMalloc) {
        instrumentMalloc(&F);
      }

      if (instrument_mem_inst.instrumentRealloc) {
        instrumentRealloc(&F);
      }
    }

    if (instrument_mem_inst.instrumentAlloca ||
        instrument_mem_inst.instrumentMalloc ||
        instrument_mem_inst.instrmentRealloc) {
          result = PreservedAnalyses::none();
    }


    for (auto &F: M) {
      for (auto &vuln : vulnerabilities) {
        result.intersect(runOnFunction(F, MAM, vuln));
      }
    }
    
    return result;
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
