/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "CVEAssert.hpp"
#include "IRUtils.hpp"
#include "Vulnerability.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <vector>

using namespace llvm;

/// This helper fn reduces redundant code
/// in the getOrCreate* functions
void validateIR(Function *F) {
  raw_ostream &out = errs();
  out << *F;
  if (verifyFunction(*F, &out)) {
    return;
  }
}

static bool patchRecording = false;
static SmallVector<llvm::Function *> patchHelpers;
static SmallVector<llvm::GlobalVariable *> patchGlobals;

static void collectReferencedGlobals(Value *V, std::set<std::string> &Names,
                                     SmallPtrSetImpl<Value *> &Visited) {
  if (!V || !Visited.insert(V).second) {
    return;
  }

  if (auto *GV = dyn_cast<GlobalValue>(V->stripPointerCasts())) {
    if (GV->hasName()) {
      Names.insert(GV->getName().str());
    }
  }

  if (auto *U = dyn_cast<User>(V)) {
    for (Value *Op : U->operands()) {
      collectReferencedGlobals(Op, Names, Visited);
    }
  }
}

static void collectReferencedGlobalsFromFunction(Function *F,
                                                 std::set<std::string> &Names) {
  if (!F || F->isDeclaration()) {
    return;
  }

  SmallPtrSet<Value *, 32> Visited;
  for (Instruction &I : instructions(F)) {
    collectReferencedGlobals(&I, Names, Visited);
  }
}

static void collectReferencedGlobalsFromGlobal(GlobalVariable *G,
                                               std::set<std::string> &Names) {
  if (!G || !G->hasInitializer()) {
    return;
  }

  SmallPtrSet<Value *, 32> Visited;
  collectReferencedGlobals(G->getInitializer(), Names, Visited);
}

static bool isRecordedFunction(Function *F,
                               const std::set<std::string> &FunctionNames) {
  return F && F->hasName() && FunctionNames.contains(F->getName().str());
}

static bool isRecordedGlobal(GlobalVariable *G,
                             const std::set<std::string> &GlobalNames) {
  return G && G->hasName() && GlobalNames.contains(G->getName().str());
}

static void stripCVEAssertMetadata(GlobalObject &GO) {
  GO.setMetadata("cve.noinstrument", nullptr);
}

static void stripCVEAssertMetadata(Function &F) {
  stripCVEAssertMetadata(cast<GlobalObject>(F));

  unsigned CVEMetadataKind = F.getContext().getMDKindID("cve.noinstrument");
  for (Instruction &I : instructions(F)) {
    I.setMetadata(CVEMetadataKind, nullptr);
  }
}

static std::string renderPatchModule(Module &SourceModule, Function *Target) {
  std::set<std::string> FunctionDefs;
  std::set<std::string> GlobalDefs;
  std::set<std::string> ReferencedGlobals;
  std::string TargetIRName;
  std::string TargetDefinitionNeedle;

  if (Target && Target->hasName()) {
    FunctionDefs.insert(Target->getName().str());
    raw_string_ostream TargetNameOS(TargetIRName);
    Target->printAsOperand(TargetNameOS, false);
    TargetNameOS.flush();
    TargetDefinitionNeedle = TargetIRName + "(";
  }

  for (Function *Helper : patchHelpers) {
    if (Helper && Helper->hasName()) {
      FunctionDefs.insert(Helper->getName().str());
    }
  }

  for (GlobalVariable *G : patchGlobals) {
    if (G && G->hasName()) {
      GlobalDefs.insert(G->getName().str());
    }
  }

  auto PatchModule = CloneModule(SourceModule);

  bool Changed;
  do {
    Changed = false;

    for (const std::string &Name : FunctionDefs) {
      Function *F = PatchModule->getFunction(Name);
      size_t OldSize = ReferencedGlobals.size();
      collectReferencedGlobalsFromFunction(F, ReferencedGlobals);
      Changed |= ReferencedGlobals.size() != OldSize;
    }

    for (const std::string &Name : GlobalDefs) {
      auto *G =
          dyn_cast_or_null<GlobalVariable>(PatchModule->getNamedValue(Name));
      size_t OldSize = ReferencedGlobals.size();
      collectReferencedGlobalsFromGlobal(G, ReferencedGlobals);
      Changed |= ReferencedGlobals.size() != OldSize;
    }

    for (const std::string &Name : ReferencedGlobals) {
      if (FunctionDefs.contains(Name) || GlobalDefs.contains(Name)) {
        continue;
      }

      if (Function *F = PatchModule->getFunction(Name)) {
        if (!F->isDeclaration() && F->getMetadata("cve.noinstrument")) {
          FunctionDefs.insert(Name);
          Changed = true;
        }
      }
    }
  } while (Changed);

  for (Function &F : *PatchModule) {
    if (isRecordedFunction(&F, FunctionDefs)) {
      stripCVEAssertMetadata(F);
    }
  }

  for (GlobalVariable &G : PatchModule->globals()) {
    if (isRecordedGlobal(&G, GlobalDefs)) {
      stripCVEAssertMetadata(G);
    }
  }

  SmallVector<GlobalAlias *> AliasesToErase;
  for (GlobalAlias &A : PatchModule->aliases()) {
    if (!A.hasName() || !ReferencedGlobals.contains(A.getName().str())) {
      AliasesToErase.push_back(&A);
    }
  }
  for (GlobalAlias *A : AliasesToErase) {
    A->eraseFromParent();
  }

  SmallVector<GlobalIFunc *> IFuncsToErase;
  for (GlobalIFunc &I : PatchModule->ifuncs()) {
    if (!I.hasName() || !ReferencedGlobals.contains(I.getName().str())) {
      IFuncsToErase.push_back(&I);
    }
  }
  for (GlobalIFunc *I : IFuncsToErase) {
    I->eraseFromParent();
  }

  SmallVector<GlobalVariable *> GlobalsToErase;
  for (GlobalVariable &G : PatchModule->globals()) {
    if (isRecordedGlobal(&G, GlobalDefs)) {
      continue;
    }

    if (G.hasName() && ReferencedGlobals.contains(G.getName().str())) {
      G.setInitializer(nullptr);
      G.setLinkage(GlobalValue::ExternalLinkage);
      continue;
    }

    GlobalsToErase.push_back(&G);
  }
  for (GlobalVariable *G : GlobalsToErase) {
    G->eraseFromParent();
  }

  SmallVector<Function *> FunctionsToErase;
  for (Function &F : *PatchModule) {
    if (isRecordedFunction(&F, FunctionDefs)) {
      continue;
    }

    if (F.hasName() && ReferencedGlobals.contains(F.getName().str())) {
      F.deleteBody();
      F.setLinkage(GlobalValue::ExternalLinkage);
      continue;
    }

    FunctionsToErase.push_back(&F);
  }
  for (Function *F : FunctionsToErase) {
    F->eraseFromParent();
  }

  PatchModule->setSourceFileName("");
  PatchModule->setTargetTriple("");
  PatchModule->setDataLayout("");

  while (!PatchModule->named_metadata_empty()) {
    PatchModule->eraseNamedMetadata(&*PatchModule->named_metadata_begin());
  }

  std::string IR;
  raw_string_ostream OS(IR);
  PatchModule->print(OS, nullptr);
  OS.flush();

  std::string FilteredIR;
  raw_string_ostream FilteredOS(FilteredIR);
  bool ReplacementMarkerEmitted = false;
  SmallVector<StringRef, 128> Lines;
  StringRef(IR).split(Lines, '\n');
  for (StringRef Line : Lines) {
    if (Line.starts_with("; ModuleID =") ||
        Line.starts_with("source_filename =") ||
        Line.starts_with("target datalayout =") ||
        Line.starts_with("target triple =")) {
      continue;
    }

    if (!ReplacementMarkerEmitted && !TargetIRName.empty() &&
        Line.starts_with("define ") && Line.contains(TargetDefinitionNeedle)) {
      FilteredOS << "; resolve.patch.replace\n";
      ReplacementMarkerEmitted = true;
    }

    FilteredOS << Line << "\n";
  }
  FilteredOS.flush();
  return FilteredIR;
}

void beginPatchRecording(void) {
  patchRecording = true;
  patchHelpers.clear();
  patchGlobals.clear();
}

void recordPatchFunction(Function *F) {
  if (!patchRecording)
    return;
  if (std::find(patchHelpers.begin(), patchHelpers.end(), F) ==
      patchHelpers.end()) {
    patchHelpers.push_back(F);
  }
}

void recordPatchGlobal(GlobalVariable *G) {
  if (!patchRecording)
    return;
  if (std::find(patchGlobals.begin(), patchGlobals.end(), G) ==
      patchGlobals.end()) {
    patchGlobals.push_back(G);
  }
}

void endPatchRecordingAndWrite(Function *F) {
  patchRecording = false;

  raw_ostream &out = errs();
  std::error_code EC;
  llvm::raw_fd_ostream patchFile("resolve-patch.ll", EC,
                                 llvm::sys::fs::OF_Append);
  if (!EC) {
    patchFile << renderPatchModule(*F->getParent(), F);
    patchFile.close();
    out << "[CVEAssert] Wrote to patch file (resolve-patch.ll).\n";
  } else {
    out << "[CVEAssert] Error: COULD NOT OPEN PATCH FILE.\n";
  }
}

void createSanitizerGateBranch(IRBuilder<> &Builder, Function *F,
                               SanitizerFlag flag, BasicBlock *DisabledBB,
                               BasicBlock *EnabledBB) {
  if (GlobalVariable *Map = getSanitizerMap(F)) {
    recordPatchGlobal(Map);
    LLVMContext &Ctx = F->getContext();
    auto i1Ty = Type::getInt1Ty(Ctx);
    auto usizeTy = Type::getInt64Ty(Ctx);
    Value *Zero = Builder.getInt64(0);
    Value *MapPtr = Builder.CreateGEP(Map->getValueType(), Map, {Zero, Zero});
    Value *MapEntry = Builder.CreateCall(
        getOrCreateSanitizerMapEntry(F->getParent()),
        {MapPtr, ConstantInt::get(usizeTy, static_cast<uint64_t>(flag))});
    Value *IsDisabled =
        Builder.CreateICmpEQ(MapEntry, ConstantInt::get(i1Ty, 0));
    Builder.CreateCondBr(IsDisabled, DisabledBB, EnabledBB);
    return;
  }

  Builder.CreateBr(EnabledBB);
}

Function *getOrCreateSanitizerMapEntry(Module *M) {
  LLVMContext &Ctx = M->getContext();
  auto boolType = Type::getInt1Ty(Ctx);
  auto ptrType = PointerType::get(Ctx, 0);
  auto indexType = Type::getInt64Ty(Ctx);
  auto sanitizerMapType = ArrayType::get(boolType, NumSanitizerFlags);

  FunctionType *mapLookupType =
      FunctionType::get(boolType, {ptrType, indexType}, false);

  Function *lookupFn =
      getOrCreateResolveHelper(M, "__resolve_get_flag", mapLookupType);
  if (!lookupFn->empty()) {
    recordPatchFunction(lookupFn);
    return lookupFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", lookupFn);
  IRBuilder<> builder(entryBB);

  // When indexing an array use two indices
  // 1. First index step from the global ptr
  // 2. Second index: the actual element index
  Argument *mapPtr = lookupFn->getArg(0);
  Argument *index = lookupFn->getArg(1);

  Value *zero = builder.getInt64(0);

  Value *flagPtr = builder.CreateGEP(sanitizerMapType, mapPtr, {zero, index});
  Value *flag = builder.CreateLoad(boolType, flagPtr);
  builder.CreateRet(flag);

  validateIR(lookupFn);
  recordPatchFunction(lookupFn);
  return lookupFn;
}

std::string getLLVMType(Type *ty) {
  // TODO: This is going to be super slow, may want to cache the computed
  // strings
  // TODO: Add mitigations to prevent really large symbol lengths
  auto escapeTypeToIdent = [](const std::string &s) {
    auto isIdentChar = [](char c) {
      return (c == '_') || std::isalnum(static_cast<unsigned char>(c));
    };

    std::string out;
    out.reserve(s.size() * 3 + 3);
    out += "ty_"; // safe prefix
    for (unsigned char c : s) {
      if (isIdentChar(c)) {
        if (c == '_') {
          out += "_5f"; // escape underscore itself
        } else {
          out += c;
        }
      } else {
        std::ostringstream oss;
        oss << '_' << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(c);
        out += oss.str();
      }
    }
    return out;
  };
  std::string canon;
  llvm::raw_string_ostream rso(canon);
  ty->print(rso);
  rso.flush();

  return escapeTypeToIdent(canon);
}

Function *getOrCreateResolveHelper(Module *M, std::string fnName,
                                   FunctionType *fnType,
                                   GlobalValue::LinkageTypes linkType) {
  LLVMContext &Ctx = M->getContext();
  if (auto handler = M->getFunction(fnName))
    return handler;

  Function *helperFn = Function::Create(fnType, linkType, fnName, M);
  helperFn->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
  return helperFn;
}

Function *getOrCreateReportSanitizerTriggered(Module *M) {
  auto &Ctx = M->getContext();
  auto voidType = Type::getVoidTy(Ctx);

  FunctionType *reportFnType = FunctionType::get(voidType, {}, false);

  Function *reportFn =
      getOrCreateResolveHelper(M, "__resolve_report_violation", reportFnType,
                               GlobalValue::WeakAnyLinkage);
  if (!reportFn->empty()) {
    recordPatchFunction(reportFn);
    return reportFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", reportFn);
  IRBuilder<> builder(entryBB);
  builder.CreateRetVoid();

  validateIR(reportFn);
  recordPatchFunction(reportFn);
  return reportFn;
}

Function *getOrCreateRecoverBufferFn(Module *M) {
  LLVMContext &Ctx = M->getContext();

  auto ptrType = PointerType::get(Ctx, 0);
  FunctionType *fnTy = FunctionType::get(ptrType, {}, false);

  auto recoverBufferFn = getOrCreateResolveHelper(
      M, "resolve_get_recover_longjmp_buf", fnTy, GlobalValue::WeakAnyLinkage);
  if (!recoverBufferFn->empty()) {
    recordPatchFunction(recoverBufferFn);
    return recoverBufferFn;
  }

  BasicBlock *entryBB = BasicBlock::Create(Ctx, "entry", recoverBufferFn);
  IRBuilder<> builder(entryBB);
  builder.CreateRet(Constant::getNullValue(ptrType));

  recoverBufferFn->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
  validateIR(recoverBufferFn);
  recordPatchFunction(recoverBufferFn);

  return recoverBufferFn;
}

Function *
getOrCreateRemediationBehavior(Module *M,
                               Vulnerability::RemediationStrategies strategy) {
  auto &Ctx = M->getContext();
  auto ptrType = PointerType::get(Ctx, 0);
  auto voidType = Type::getVoidTy(Ctx);
  auto intType = Type::getInt32Ty(Ctx);

  FunctionType *fnTy = FunctionType::get(voidType, {}, false);

  std::string fnName;
  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT:
    fnName = "__resolve_exit";
    break;
  case Vulnerability::RemediationStrategies::RECOVER:
    fnName = "__resolve_recover";
    break;
  default:
    return nullptr;
  }

  Function *fn = getOrCreateResolveHelper(M, fnName, fnTy);
  if (!fn->empty()) {
    recordPatchFunction(fn);
    return fn;
  }

  AttrBuilder FnAttrs(Ctx);
  FnAttrs.addAttribute(Attribute::NoReturn);
  AttributeList attrs =
      AttributeList::get(Ctx, AttributeList::FunctionIndex, FnAttrs);

  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", fn);
  IRBuilder<> builder(BB);

  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT: {
    FunctionType *exitType = FunctionType::get(voidType, {intType}, false);
    FunctionCallee exitFn = M->getOrInsertFunction("_exit", exitType);
    builder.CreateCall(exitFn, {builder.getInt32(3)});
    builder.CreateUnreachable();
    break;
  }

  case Vulnerability::RemediationStrategies::RECOVER: {
    FunctionCallee longjmpFn = M->getOrInsertFunction(
        "longjmp", FunctionType::get(voidType, {ptrType, intType}, false));

    Function *recoverBufferFn = getOrCreateRecoverBufferFn(M);
    Value *buf = builder.CreateCall(recoverBufferFn);
    builder.CreateCall(longjmpFn, {buf, builder.getInt32(42)});
    builder.CreateUnreachable();
    break;
  }

  default:
    llvm_unreachable("Unsupported remediation strategy");
  }

  validateIR(fn);
  recordPatchFunction(fn);
  return fn;
}
