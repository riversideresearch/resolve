/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

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

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "CVEAssert.hpp"
#include "Vulnerability.hpp"

#include "arith_san.hpp"
#include "bounds_check.hpp"
#include "helpers.hpp"
#include "instrument.hpp"
#include "null_ptr.hpp"
#include "undesirableop.hpp"

using namespace llvm;

// Global env var
bool CVE_ASSERT_DEBUG; 


GlobalVariable* initSanitizerMap(Module *M) {
    LLVMContext &Ctx = M->getContext();
    ArrayType *arrty = ArrayType::get(Type::getInt1Ty(Ctx), 7);
    
    M->getOrInsertGlobal("sanitizer_map", arrty);
    GlobalVariable *gSanitizerMap = M->getNamedGlobal("sanitizer_map");
    
    gSanitizerMap->setLinkage(GlobalValue::ExternalLinkage);
    gSanitizerMap->setConstant(false);

    if (!gSanitizerMap->hasInitializer()) {
      std::vector<Constant *> elems(7, ConstantInt::get(Type::getInt1Ty(Ctx), 1));
      gSanitizerMap->setInitializer(ConstantArray::get(arrty, elems));
    }

    return gSanitizerMap;
}

namespace {

struct InstrumentMemInst {
  bool instrumentMemAllocator = false;
  bool instrumentAlloca = false;
};

struct LabelCVEPass : public PassInfoMixin<LabelCVEPass> {
  std::vector<Vulnerability> vulnerabilities;

  enum VulnID {
    ALL = 0,
    STACK_BASED_BUF_OVERFLOW = 121,
    HEAP_BASED_BUF_OVERFLOW = 122,
    WRITE_WHAT_WHERE = 123,
    OOB_WRITE = 787,
    OOB_READ = 125, /* NOTE: This ID corresponds to CWE-ID description found in
                       stb-resize, lamartine CPs */
    INCORRECT_BUF_SIZE = 131, /* NOTE: This ID corresponds to the CWE-ID
                                 description found in analyze image CP*/
    DIVIDE_BY_ZERO = 369,     /* NOTE: This ID corresponds to CWE description in
                                 ros2 challenge problem */
    INT_OVERFLOW =
        190, /* NOTE: This ID corresponds to CWE-ID description in redis  */
    NULL_PTR_DEREF = 476, /* NOTE: This ID has been found in OpenALPR, NASA CFS,
                             stb-convert CPs */
    STACK_FREE =
        590 /* NOTE: This ID has been found in NASA CFS challenge problem */
  };

  LabelCVEPass() {
    // Initialize env var
    CVE_ASSERT_DEBUG = strlen(std::getenv("CVE_ASSERT_DEBUG") ?: "") > 0;

    vulnerabilities = Vulnerability::parseVulnerabilityFile();
  }

  std::string demangleFunctionName(Function &F) {
    std::string demangledName = "";
    char *demangledNamePtr = llvm::itaniumDemangle(F.getName().str(), false);
    if (demangledNamePtr) {
      demangledName = demangledNamePtr;
    }

    return demangledName;
  }

  bool matchTargetFunctionName(std::string fn_name, Function &F, Vulnerability &vuln) {
    if (vuln.TargetFunctionName.empty() ||
      (fn_name.find(vuln.TargetFunctionName) == std::string::npos &&
      F.getName().str().find(vuln.TargetFunctionName) == std::string::npos)) {
        return false;
      }
    return true;
  } 

  Function *getOrCreateFreeOfNonHeapSanitizer(
      Module *M, Vulnerability::RemediationStrategies strategy) {
    std::string handlerName = "resolve_sanitize_non_heap_free";
    LLVMContext &Ctx = M->getContext();

    IRBuilder<> builder(Ctx);
    // TODO: handle address spaces other than 0
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto usize_ty = Type::getInt64Ty(Ctx);

    // TODO: write this in asm as some kind of sanitzer_rt?
    FunctionType *resolveFreeNonHeapFnTy =
        FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty}, false);
    Function *resolveFreeNonHeapFn = getOrCreateResolveHelper(
      M, handlerName, resolveFreeNonHeapFnTy);
    if (!resolveFreeNonHeapFn->empty()) { return resolveFreeNonHeapFn; }
    

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", resolveFreeNonHeapFn);
    BasicBlock *CheckOnHeapBB = BasicBlock::Create(Ctx, "check_heap", resolveFreeNonHeapFn);
    BasicBlock *SanitizeNonHeapBB =
        BasicBlock::Create(Ctx, "sanitize_nonheap", resolveFreeNonHeapFn);
    BasicBlock *FreeHeapBB = BasicBlock::Create(Ctx, "free_heap", resolveFreeNonHeapFn);

    // Set insertion point to entry block
    builder.SetInsertPoint(EntryBB);
    Argument *inputPtr = resolveFreeNonHeapFn->getArg(0);

    Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M), { ConstantInt::get(usize_ty, 2)});
    Value *isZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(usize_ty, 0));
    builder.CreateCondBr(isZero, FreeHeapBB, CheckOnHeapBB);

    // Call Is Heap Func
    // Branch if True
    builder.SetInsertPoint(CheckOnHeapBB);
    Value *IsHeap = builder.CreateCall(getOrCreateIsHeap(M, Ctx), {inputPtr});
    builder.CreateCondBr(IsHeap, FreeHeapBB, SanitizeNonHeapBB);

    // Sanitize Block: Call getOrCreateRemediationBehavior
    builder.SetInsertPoint(SanitizeNonHeapBB);
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy), {});
    builder.CreateRetVoid();

    // Free Block: call Free
    builder.SetInsertPoint(FreeHeapBB);
    builder.CreateCall(M->getFunction("free"), {inputPtr});
    builder.CreateRetVoid();

    validateIR(resolveFreeNonHeapFn);
    return resolveFreeNonHeapFn;
  }

  void sanitizeFreeOfNonHeap(Function *F,
                             Vulnerability::RemediationStrategies strategy) {
    LLVMContext &Ctx = F->getContext();
    IRBuilder<> builder(Ctx);
    std::vector<CallInst *> workList;

    for (auto &BB : *F) {
      for (auto &Inst : BB) {
        if (auto *call = dyn_cast<CallInst>(&Inst)) {
          if (auto callee = call->getCalledFunction())
            if (callee->getName() == "free") {
              workList.push_back(call);
            }
        }
      }
    }

    for (auto call : workList) {
      builder.SetInsertPoint(call);
      auto sanitizerFn =
          getOrCreateFreeOfNonHeapSanitizer(F->getParent(), strategy);

      builder.CreateCall(sanitizerFn, {call->getArgOperand(0)});
      call->removeFromParent();
      call->deleteValue();
    }
  }

  void applyAutomaticSanitizers(Function &F, Vulnerability::RemediationStrategies strategy) {
    /// applies all automatic sanitizers (operation masking excluded)
    sanitizeFreeOfNonHeap(&F, strategy);
    sanitizeMemInstBounds(&F, strategy);
    sanitizeNullPointers(&F, strategy);
    sanitizeDivideByZero(&F, strategy);
    sanitizeIntOverflow(&F, strategy);
  }

  /// For each function, if it matches the target function name, insert calls to
  /// the vulnerability handlers as specified in the JSON. Each call receives
  /// the triggering argument parsed from the JSON.
  PreservedAnalyses runOnFunction(Function &F, ModuleAnalysisManager &MAM,
                                  Vulnerability &vuln) {
    auto result = PreservedAnalyses::all();
    raw_ostream &out = errs();
    
    if (F.getMetadata("resolve.noinstrument")) { return result; }

    std::string demangledFnName = demangleFunctionName(F); 

    if (CVE_ASSERT_DEBUG) {
      errs() << "[CVEAssert] Trying fn " << F.getName()
             << " Demangled name: " << demangledFnName << "\n";
    }

    if (!matchTargetFunctionName(demangledFnName, F, vuln)) {
      return result;
    }

    out << "[CVEAssert] === Pre Instrumented IR === \n";
    out << F;

    if (vuln.UndesirableFunction.has_value()) {
      /* NOTE: We are using '0' as a temporary this will be updated future PRs
       */
      sanitizeUndesirableOperationInFunction(&F, *vuln.UndesirableFunction, 0);
      result = PreservedAnalyses::none();
      out << "[CVEAssert] === Post Sanitization of Undesirable Operation IR "
             "=== \n";
      out << F;
    }

    if (vuln.Strategy == Vulnerability::RemediationStrategies::NONE) {
      errs() << "[CVEAssert] NONE strategy selected for " << vuln.TargetFileName
             << ":" << vuln.TargetFunctionName << "...\n";
      errs() << "[CVEAssert] Skipping remediation\n";
      return result;
    }

    switch (vuln.WeaknessID) {
    case VulnID::STACK_BASED_BUF_OVERFLOW: /* Stack-based buffer overflow */
    case VulnID::HEAP_BASED_BUF_OVERFLOW:  /* Heap-base buffer overflow */
    case VulnID::OOB_WRITE:                /* OOB Write */
    case VulnID::WRITE_WHAT_WHERE:
      sanitizeMemInstBounds(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::OOB_READ: /* OOB Read; found in stb-resize, lamartine challenge
                              problems */
    case VulnID::INCORRECT_BUF_SIZE: /* Incorrect buffer size calculation; found
                                        in analyze-image */
      sanitizeMemInstBounds(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::DIVIDE_BY_ZERO: /* Divide by Zero; found in ros2 and
                                    analyze-image */
      /* Workaround for ambiguous CWE description in analyze-image */
      sanitizeDivideByZero(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::INT_OVERFLOW: /* Integer Overflow */
      sanitizeIntOverflow(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::NULL_PTR_DEREF: /* Null Pointer Dereference; Found in openalpr,
                                    nasa-cfs, stb-convert*/
      sanitizeNullPointers(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::STACK_FREE: /* Stack free;  Found in nasa-cfs */
      sanitizeFreeOfNonHeap(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::ALL:
      applyAutomaticSanitizers(F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    default:
      errs() << "[CVEAssert] Error: CWE " << vuln.WeaknessID
             << " not implemented\n";
      break;
    }

    out << "[CVEAssert] === Post Instrumented IR === \n";
    out << F;

    if (verifyFunction(F, &out)) {
      report_fatal_error("[CVEAssert] We broke something");
    }

    errs() << "[CVEAssert] Inserted vulnerability handler calls in function "
           << vuln.TargetFileName << ":" << vuln.TargetFunctionName << "\n";
    return result;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    auto result = PreservedAnalyses::all();
    InstrumentMemInst instrument_mem_inst;

    initSanitizerMap(&M);

    for (auto &vuln : vulnerabilities) {
      // Also skip instrumentation for skipped vulnerabilities
      if (vuln.Strategy == Vulnerability::RemediationStrategies::NONE) {
        continue;
      }

      switch (vuln.WeaknessID) {
      // 121 stack-based
      case VulnID::STACK_BASED_BUF_OVERFLOW:
        instrument_mem_inst.instrumentAlloca = true;
        break;

      // 122 heap-based
      case VulnID::HEAP_BASED_BUF_OVERFLOW:
        instrument_mem_inst.instrumentMemAllocator = true;
        break;

      // default instrument both
      case VulnID::OOB_READ:
      case VulnID::OOB_WRITE:
      case VulnID::INCORRECT_BUF_SIZE:
      case VulnID::WRITE_WHAT_WHERE:
        instrument_mem_inst.instrumentAlloca = true;
        instrument_mem_inst.instrumentMemAllocator = true;
        break;
      }
    }

    for (auto &F : M) {
      if (instrument_mem_inst.instrumentAlloca) {
        instrumentAlloca(&F);
      }

      if (instrument_mem_inst.instrumentMemAllocator) {
        instrumentLibraryAllocations(&F);
      }
    }

    for (auto &F : M) {
      for (auto &vuln : vulnerabilities) {
        result.intersect(runOnFunction(F, MAM, vuln));
      }
    }

    if (instrument_mem_inst.instrumentAlloca ||
        instrument_mem_inst.instrumentMemAllocator) {
      result = PreservedAnalyses::none();
    }
    return result;
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