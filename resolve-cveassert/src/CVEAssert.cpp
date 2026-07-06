/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/DenseMap.h"
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
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "ArithmeticSanitizer.hpp"
#include "BoundsCheck.hpp"
#include "CVEAssert.hpp"
#include "FreeNonHeapMem.hpp"
#include "IRUtils.hpp"
#include "InstrumentAllocators.hpp"
#include "NullPointerSanitizer.hpp"
#include "OperationMasking.hpp"
#include "Vulnerability.hpp"

using namespace llvm;

// Global env var
bool CVE_ASSERT_DEBUG;
DenseMap<Function *, GlobalVariable *> SanitizerMaps;

GlobalVariable *getSanitizerMap(Function *F) {
  auto It = SanitizerMaps.find(F);
  if (It == SanitizerMaps.end()) {
    return nullptr;
  }
  return It->second;
}

GlobalVariable *initSanitizerMap(Function &F) {
  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();
  Type *i1_ty = Type::getInt1Ty(Ctx);
  ArrayType *arr_ty = ArrayType::get(i1_ty, 6);

  std::string globalName = F.getName().str() + ".sanmap";

  Constant *gv = M->getOrInsertGlobal(globalName, arr_ty);
  // cast<> performs an implicit assertion for Constant -> GlobalVariable
  auto *gSanitizerMap = cast<GlobalVariable>(gv);

  gSanitizerMap->setLinkage(GlobalValue::LinkOnceAnyLinkage);
  gSanitizerMap->setConstant(false);
  gSanitizerMap->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));

  if (!gSanitizerMap->hasInitializer()) {
    std::vector<Constant *> elems(6, ConstantInt::get(i1_ty, 1));
    gSanitizerMap->setInitializer(ConstantArray::get(arr_ty, elems));
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
    OOB = 119,
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
        590, /* NOTE: This ID has been found in NASA CFS challenge problem */
    INCORRECT_BITWISE_SHIFT =
        1335 /* https://cwe.mitre.org/data/definitions/1335.html */
  };

  LabelCVEPass() {
    // Initialize env var
    CVE_ASSERT_DEBUG = strlen(std::getenv("CVE_ASSERT_DEBUG") ?: "") > 0;

    vulnerabilities = Vulnerability::parseVulnerabilityFile();
  }

  void applyAutomaticSanitizers(Function &F,
                                Vulnerability::RemediationStrategies strategy) {
    /// applies all automatic sanitizers (operation masking excluded)
    sanitizeFreeOfNonHeap(&F, strategy);
    sanitizeMemInstBounds(&F, strategy);
    sanitizeNullPointers(&F, strategy);
    sanitizeDivideByZero(&F, strategy);
    sanitizeIntOverflow(&F, strategy);
    sanitizeBitShift(&F, strategy);
  }

  /// Return true if F's name (raw or demangled) matches or contains targetName.
  /// Caret/dollar anchors request exact matching
  /// Always returns true if targetName is empty
  bool nameMatches(Function &F, const std::string &demangledName,
                   const std::string &targetName) {
    // Empty function name matches all functions
    if (targetName.empty()) {
      return true;
    }

    if (targetName.size() >= 2 && targetName.front() == '^' &&
        targetName.back() == '$') {
      std::string exactName = targetName.substr(1, targetName.size() - 2);
      return demangledName == exactName || F.getName() == exactName;
    }

    // First check demangled name
    if (demangledName.find(targetName) != std::string::npos) {
      return true;
    }

    // Next fallback to raw symbols
    if (F.getName().str().find(targetName) != std::string::npos) {
      return true;
    }

    return false;
  }

  /// Return true if `F` meets instrumentation critera for vuln
  bool shouldInstrument(Function &F, Vulnerability &vuln) {
    // Skip noinstrument functions
    if (F.getMetadata("cve.noinstrument")) {
      return false;
    }

    char *demangledNamePtr = llvm::itaniumDemangle(F.getName().str(), false);
    std::string demangledName(demangledNamePtr ?: "");

    if (CVE_ASSERT_DEBUG) {
      errs() << "[CVEAssert] Trying fn " << F.getName()
             << " Demangled name: " << demangledName << "\n";
    }

    return nameMatches(F, demangledName, vuln.TargetFunctionName);
  }

  /// For each function, if it matches the target function name, insert calls to
  /// the vulnerability handlers as specified in the JSON. Each call receives
  /// the triggering argument parsed from the JSON.
  PreservedAnalyses runOnFunction(Function &F, ModuleAnalysisManager &MAM,
                                  Vulnerability &vuln) {
    auto result = PreservedAnalyses::all();

    if (!shouldInstrument(F, vuln)) {
      return result;
    }

    raw_ostream &out = errs();

    out << "[CVEAssert] === Pre Instrumented IR === \n";
    out << F;
    out << "[CVEAssert] === Inserted Sanitizer Helpers === \n";

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
      out << "[CVEAssert] NONE strategy selected for " << vuln.TargetFileName
          << ":" << vuln.TargetFunctionName << "...\n";
      out << "[CVEAssert] Skipping remediation\n";
      return result;
    }

    switch (vuln.WeaknessID) {
    case VulnID::STACK_BASED_BUF_OVERFLOW: /* Stack-based buffer overflow */
    case VulnID::HEAP_BASED_BUF_OVERFLOW:  /* Heap-base buffer overflow */
    case VulnID::OOB_WRITE:                /* OOB Write */
    case VulnID::OOB:
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

    case VulnID::INCORRECT_BITWISE_SHIFT:
      sanitizeBitShift(&F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    case VulnID::ALL:
      applyAutomaticSanitizers(F, vuln.Strategy);
      result = PreservedAnalyses::none();
      break;

    default:
      out << "[CVEAssert] Error: CWE " << vuln.WeaknessID
          << " not implemented\n";
      break;
    }

    out << "[CVEAssert] === Post Instrumented IR === \n";
    validateIR(&F);

    out << "[CVEAssert] Inserted vulnerability handler calls in function "
        << vuln.TargetFileName << ":" << vuln.TargetFunctionName << "\n";
    return result;
  }

  void registerGlobals(Module &M) {
    if (M.getFunction("__resolve_register_globals_ctor"))
      return;

    LLVMContext &Ctx = M.getContext();
    const DataLayout &DL = M.getDataLayout();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto size_ty = Type::getInt64Ty(Ctx);
    auto void_ty = Type::getVoidTy(Ctx);

    FunctionCallee registerFn = M.getOrInsertFunction(
        "__resolve_register_global",
        FunctionType::get(void_ty, {ptr_ty, size_ty}, false));

    SmallVector<GlobalVariable *, 16> targets;
    for (GlobalVariable &G : M.globals()) {
      if (G.isDeclaration()) // external: defining TU registers it
        continue;
      if (G.isThreadLocal()) // TLS: ctor captures one thread's &G
        continue;
      if (G.getType()->getPointerAddressSpace() !=
          0) // non-default AS: not flat-addressable
        continue;
      if (G.getName().starts_with("llvm.")) // used/global_ctors/metadata
        continue;
      if (G.getName().starts_with("__resolve_"))
        continue;
      if (DL.getTypeAllocSize(G.getValueType()) == 0)
        continue;
      targets.push_back(&G);
    }

    if (targets.empty())
      return;

    Function *ctor = Function::Create(FunctionType::get(void_ty, {}, false),
                                      GlobalValue::InternalLinkage,
                                      "__resolve_register_globals_ctor", &M);

    ctor->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));

    IRBuilder<> builder(BasicBlock::Create(Ctx, "entry", ctor));
    for (GlobalVariable *G : targets) {
      uint64_t size = DL.getTypeAllocSize(G->getValueType());
      builder.CreateCall(registerFn, {G, ConstantInt::get(size_ty, size)});
    }
    builder.CreateRetVoid();

    appendToGlobalCtors(M, ctor, 0);
  }

  PreservedAnalyses
  runInstrumentationPipeline(Module &M, ModuleAnalysisManager &MAM,
                             std::vector<Vulnerability> &vulns,
                             bool writePatch) {
    auto result = PreservedAnalyses::all();
    InstrumentMemInst instrument_mem_inst;

    SanitizerMaps.clear();

    /// Precompute globals before instrumentation
    for (auto &F : M) {
      for (auto &vuln : vulns) {
        if (F.isDeclaration())
          continue;

        if (vuln.Gated && shouldInstrument(F, vuln)) {
          SanitizerMaps[&F] = initSanitizerMap(F);
        }
      }
    }

    for (auto &vuln : vulns) {
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
      case VulnID::OOB:
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
      if (F.isDeclaration())
        continue;

      if (instrument_mem_inst.instrumentAlloca) {
        instrumentAlloca(&F);
      }

      if (instrument_mem_inst.instrumentMemAllocator) {
        instrumentLibraryAllocations(&F);
      }
    }

    for (auto &F : M) {
      if (F.isDeclaration())
        continue;

      for (auto &vuln : vulns) {
        if (writePatch) {
          if (!shouldInstrument(F, vuln))
            continue;

          beginPatchRecording();
          result.intersect(runOnFunction(F, MAM, vuln));
          endPatchRecordingAndWrite(&F);
        } else {
          result.intersect(runOnFunction(F, MAM, vuln));
        }
      }
    }

    if (!writePatch && (instrument_mem_inst.instrumentAlloca ||
                        instrument_mem_inst.instrumentMemAllocator)) {
      registerGlobals(M);
      result = PreservedAnalyses::none();
    }
    return result;
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    std::vector<Vulnerability> patchVulns;
    std::vector<Vulnerability> moduleVulns;

    for (auto &vuln : vulnerabilities) {
      if (vuln.Output == Vulnerability::RemediationOutput::PATCH) {
        patchVulns.push_back(vuln);
      } else {
        moduleVulns.push_back(vuln);
      }
    }

    if (!patchVulns.empty()) {
      std::error_code EC;
      raw_fd_ostream patchFile("resolve-patch.ll", EC);
      patchFile.close();
    }

    for (auto &vuln : patchVulns) {
      auto patchModule = CloneModule(M);
      std::vector<Vulnerability> singleVuln = {vuln};
      runInstrumentationPipeline(*patchModule, MAM, singleVuln, true);
    }

    return runInstrumentationPipeline(M, MAM, moduleVulns, false);
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
