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
#include "Vulnerability.hpp"
#include "helpers.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <set>
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
static std::vector<llvm::Function *> patchHelpers;
static std::vector<llvm::GlobalVariable *> patchGlobals;

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
      auto *G = dyn_cast_or_null<GlobalVariable>(PatchModule->getNamedValue(Name));
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

  std::vector<GlobalAlias *> AliasesToErase;
  for (GlobalAlias &A : PatchModule->aliases()) {
    if (!A.hasName() || !ReferencedGlobals.contains(A.getName().str())) {
      AliasesToErase.push_back(&A);
    }
  }
  for (GlobalAlias *A : AliasesToErase) {
    A->eraseFromParent();
  }

  std::vector<GlobalIFunc *> IFuncsToErase;
  for (GlobalIFunc &I : PatchModule->ifuncs()) {
    if (!I.hasName() || !ReferencedGlobals.contains(I.getName().str())) {
      IFuncsToErase.push_back(&I);
    }
  }
  for (GlobalIFunc *I : IFuncsToErase) {
    I->eraseFromParent();
  }

  std::vector<GlobalVariable *> GlobalsToErase;
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

  std::vector<Function *> FunctionsToErase;
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
  if (!patchRecording) return;
  if (std::find(patchHelpers.begin(), patchHelpers.end(), F) == patchHelpers.end()) {
    patchHelpers.push_back(F);
  }
}

void recordPatchGlobal(GlobalVariable *G) {
  if (!patchRecording) return;
  if (std::find(patchGlobals.begin(), patchGlobals.end(), G) == patchGlobals.end()) {
    patchGlobals.push_back(G);
  }
}

void endPatchRecordingAndWrite(Function *F) {
  patchRecording = false;

  raw_ostream &out = errs();
  std::error_code EC;
  llvm::raw_fd_ostream patchFile("resolve-patch.ll", EC, llvm::sys::fs::OF_Append);
  if(!EC) {
    patchFile << renderPatchModule(*F->getParent(), F);
    patchFile.close();
    out << "[CVEAssert] Wrote to patch file (resolve-patch.ll).\n";
  }
  else {
    out << "[CVEAssert] Error: COULD NOT OPEN PATCH FILE.\n";
  }
}

Function *getOrCreateSanitizerMapEntry(Module *M) {
  LLVMContext &Ctx = M->getContext();
  auto i1_ty = Type::getInt1Ty(Ctx);
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto usize_ty = Type::getInt64Ty(Ctx);
  auto arr_ty = ArrayType::get(i1_ty, 6);

  FunctionType *sanitizerMapIdxFnTy =
      FunctionType::get(i1_ty, {ptr_ty, usize_ty}, false);

  Function *sanitizerMapIdxFn =
      getOrCreateResolveHelper(M, "__cve_get_flag", sanitizerMapIdxFnTy);
  if (!sanitizerMapIdxFn->empty()) {
    recordPatchFunction(sanitizerMapIdxFn);
    return sanitizerMapIdxFn;
  }

  IRBuilder<> builder(Ctx);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", sanitizerMapIdxFn);
  builder.SetInsertPoint(EntryBB);

  // When indexing an array use two indices
  // 1. First index step from the global ptr
  // 2. Second index: the actual element index
  Argument *mapPtr = sanitizerMapIdxFn->getArg(0);
  Argument *idx = sanitizerMapIdxFn->getArg(1);

  Value *zero = builder.getInt64(0);

  Value *sanitizerMapPtr = builder.CreateGEP(arr_ty, mapPtr, {zero, idx});
  Value *flag = builder.CreateLoad(i1_ty, sanitizerMapPtr);
  builder.CreateRet(flag);

  validateIR(sanitizerMapIdxFn);
  recordPatchFunction(sanitizerMapIdxFn);
  return sanitizerMapIdxFn;
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

Function *getOrCreateResolveHelper(Module *M, std::string fn_name,
                                   FunctionType *fn_type,
                                   GlobalValue::LinkageTypes link_type) {
  LLVMContext &Ctx = M->getContext();
  if (auto handler = M->getFunction(fn_name))
    return handler;

  Function *resolveHelperFn = Function::Create(fn_type, link_type, fn_name, M);
  resolveHelperFn->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
  return resolveHelperFn;
}

Function *getOrCreateIsHeap(Module *M, LLVMContext &Ctx) {
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i1_ty = Type::getInt1Ty(Ctx);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *resolveIsHeapFnTy = FunctionType::get(i1_ty, {ptr_ty}, false);

  Function *resolveIsHeapFn =
      getOrCreateResolveHelper(M, "__cve_is_heap", resolveIsHeapFnTy);

  if (!resolveIsHeapFn->empty()) {
    recordPatchFunction(resolveIsHeapFn);
    return resolveIsHeapFn;
  }

  IRBuilder<> Builder(Ctx);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", resolveIsHeapFn);
  Builder.SetInsertPoint(Entry);

  // Get function argument
  Argument *InputPtr = resolveIsHeapFn->getArg(0);

  FunctionType *AsmType = FunctionType::get(ptr_ty, {});
  auto read_sp_asm = InlineAsm::get(AsmType, "mov %rsp, $0",
                                    "=r,~{dirflag},~{fpsr},~{flags}", true);
  auto read_sp = Builder.CreateCall(read_sp_asm, {});
  // ($rsp <= InputPtr)
  auto is_stack = Builder.CreateICmpULE(read_sp, InputPtr);

  auto start = M->getOrInsertGlobal("_start", Type::getInt8Ty(Ctx));
  auto end = M->getOrInsertGlobal("_end", Type::getInt8Ty(Ctx));

  // ((InputPtr >= _start) && (InputPtr <= _end))
  auto is_static = Builder.CreateAnd({
      Builder.CreateICmpUGE(InputPtr, start),
      Builder.CreateICmpULE(InputPtr, end),
  });

  // return !(is_stack || is_static);
  auto result = Builder.CreateNot(Builder.CreateOr({is_stack, is_static}));
  Builder.CreateRet(result);

  validateIR(resolveIsHeapFn);
  recordPatchFunction(resolveIsHeapFn);
  return resolveIsHeapFn;
}

Function *getOrCreateResolveReportSanitizerTriggered(Module *M) {
  auto &Ctx = M->getContext();
  auto void_ty = Type::getVoidTy(Ctx);

  FunctionType *resolveReportFnTy = FunctionType::get(void_ty, {}, false);

  Function *resolveReportFn =
      getOrCreateResolveHelper(M, "__resolve_report_violation",
                               resolveReportFnTy, GlobalValue::WeakAnyLinkage);
  if (!resolveReportFn->empty()) {
    recordPatchFunction(resolveReportFn);
    return resolveReportFn;
  }

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolveReportFn);
  IRBuilder<> builder(EntryBB);
  builder.CreateRetVoid();

  validateIR(resolveReportFn);
  recordPatchFunction(resolveReportFn);
  return resolveReportFn;
}

Function *getOrCreateRecoverBufferFunction(Module *M) {
  LLVMContext &Ctx = M->getContext();

  auto ptr_ty = PointerType::get(M->getContext(), 0);
  FunctionType *resolve_recover_buf_fn_ty =
      FunctionType::get(ptr_ty, {}, false);

  auto resolveRecoverFn = getOrCreateResolveHelper(
      M, "resolve_get_recover_longjmp_buf", resolve_recover_buf_fn_ty,
      GlobalValue::WeakAnyLinkage);
  if (!resolveRecoverFn->empty()) {
    recordPatchFunction(resolveRecoverFn);
    return resolveRecoverFn;
  }

  BasicBlock *EntryBB =
      BasicBlock::Create(M->getContext(), "", resolveRecoverFn);
  IRBuilder<> builder(EntryBB);
  builder.SetInsertPoint(EntryBB);
  builder.CreateRet(Constant::getNullValue(ptr_ty));

  resolveRecoverFn->setMetadata("cve.noinstrument", MDNode::get(Ctx, {}));
  validateIR(resolveRecoverFn);
  recordPatchFunction(resolveRecoverFn);

  return resolveRecoverFn;
}

Function *
getOrCreateRemediationBehavior(Module *M,
                               Vulnerability::RemediationStrategies strategy) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i32_ty = Type::getInt32Ty(Ctx);

  FunctionType *fnTy = FunctionType::get(void_ty, {}, false);

  std::string fnName;
  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT:
    fnName = "__cve_exit";
    break;
  case Vulnerability::RemediationStrategies::RECOVER:
    fnName = "__cve_recover";
    break;
  default:
    return nullptr;
  }

  Function *fn = getOrCreateResolveHelper(M, fnName, fnTy);
  if (!fn->empty()) {
    recordPatchFunction(fn);
    return fn;
  }

  BasicBlock *BB = BasicBlock::Create(Ctx, "entry", fn);
  IRBuilder<> builder(BB);

  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT: {
    FunctionType *exitTy = FunctionType::get(void_ty, {i32_ty}, false);
    FunctionCallee exitFn = M->getOrInsertFunction("_exit", exitTy);
    builder.CreateCall(exitFn, {builder.getInt32(3)});
    builder.CreateUnreachable();
    break;
  }

  case Vulnerability::RemediationStrategies::RECOVER: {
    FunctionCallee longjmpFn = M->getOrInsertFunction(
        "longjmp", FunctionType::get(void_ty, {ptr_ty, i32_ty}, false));

    Function *resolveRecoverFn = getOrCreateRecoverBufferFunction(M);
    Value *buf = builder.CreateCall(resolveRecoverFn);
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
