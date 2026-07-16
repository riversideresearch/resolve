/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "resolve_facts_llvm/resolve_facts_llvm.hpp"

#include <cstdlib> // For std::getenv
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "llvm/Support/Compression.h"

using namespace llvm;

std::string resolve::typeToString(const Type &type) {
  std::string str;
  llvm::raw_string_ostream out(str);
  type.print(out);
  return str;
}

void resolve::getGlobalFacts(LLVMFacts &facts, GlobalVariable &G) {
  facts.addNode(G);
  facts.setName(G, G.getName());
  facts.setLinkage(G, G.hasExternalLinkage() ? Linkage::ExternalLinkage
                                             : Linkage::Other);
}

static std::string getFunctionNameFromDebugInfo(Function &F) {
  // Each function may have a DISubprogram attached
  if (auto *SP = F.getSubprogram()) {
    if (auto *File = SP->getFile()) {
      return (File->getDirectory() + "/" + File->getFilename()).str();
    }
  }
  return "";
}

void resolve::getFunctionFacts(LLVMFacts &facts, Function &F) {
  facts.addNode(F);
  facts.setName(F, F.getName());
  facts.setLinkage(F, F.hasExternalLinkage() ? Linkage::ExternalLinkage
                                             : Linkage::Other);
  facts.setFunctionType(F, typeToString(*F.getFunctionType()));
  auto name = getFunctionNameFromDebugInfo(F);
  if (!name.empty()) {
    facts.setSourceFile(F, name);
  }
  if (F.hasAddressTaken()) {
    facts.setAddressTaken(F);
  }

  if (F.isDeclaration())
    return;

  facts.addEdge(F, F.getEntryBlock(), EdgeKind::EntryPoint);

  for (Argument &A : F.args()) {
    facts.addEdge(F, A, EdgeKind::Contains);
    facts.setIdx(A, A.getArgNo());
  }

  for (BasicBlock &BB : F) {
    facts.addEdge(F, BB, EdgeKind::Contains);
    facts.setIdx(BB, LLVMFacts::getIndexInParent(BB));
    if (BB.hasName()) {
      facts.setName(BB, BB.getName());
    }

    // Control flow Edges
    for (BasicBlock *Succ : successors(&BB)) {
      facts.addEdge(BB, *Succ, EdgeKind::ControlFlowTo);
    }

    for (Instruction &I : BB) {
      facts.addEdge(BB, I, EdgeKind::Contains);
      facts.setOpcode(I, I.getOpcodeName());
      if (auto dbgLoc = I.getDebugLoc()) {
        facts.setSourceLoc(I, dbgLoc.getLine(), dbgLoc.getCol());
      }

      // Data–flow edges: from each operand (if an instruction) to I.
      for (Value *op : I.operands()) {
        if (Instruction *opI = dyn_cast<Instruction>(op)) {
          facts.addEdge(*opI, I, EdgeKind::DataFlowTo);
        } else if (Argument *opA = dyn_cast<Argument>(op)) {
          facts.addEdge(*opA, I, EdgeKind::DataFlowTo);
        } else if (GlobalVariable *opG = dyn_cast<GlobalVariable>(op)) {
          facts.addEdge(I, *opG, EdgeKind::References);
        } else if (Function *opF = dyn_cast<Function>(op)) {
          facts.addEdge(I, *opF, EdgeKind::References);
        }
      }

      // Call edge: record call relationship at the instruction level only.
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        CallType ct;
        if (Function *Callee = CB->getCalledFunction()) {
          facts.addEdge(I, *Callee, EdgeKind::Calls);
          ct = CallType::Direct;
        } else {
          // Indirect call
          ct = CallType::Indirect;
        }

        facts.setCallType(I, ct);
        facts.setFunctionType(I, typeToString(*CB->getFunctionType()));
      }
    }
  }
}

void resolve::getModuleFacts(LLVMFacts &facts, Module &M) {
  facts.setSourceFile(M, M.getSourceFileName());

  for (GlobalVariable &G : M.globals()) {
    facts.addEdge(M, G, EdgeKind::Contains);

    getGlobalFacts(facts, G);
  }

  for (Function &F : M) {
    facts.addEdge(M, F, EdgeKind::Contains);

    getFunctionFacts(facts, F);
  }
}

// Embed the accumulated facts into custom ELF sections.
void resolve::embedFacts(Module &M, ArrayRef<uint8_t> facts) {
  LLVMContext &C = M.getContext();
  auto embedFactsSection = [&](StringRef sectionName,
                               ArrayRef<uint8_t> inputData) {
    SmallVector<uint8_t> compressedFacts;

    if (std::getenv("RESOLVE_IGNORE_COMPRESSION")) {
      compressedFacts = SmallVector<uint8_t>(inputData);
    } else {
      compression::Params params(compression::Format::Zstd);
      compression::compress(params, inputData, compressedFacts);
    }

    // errs() << "Embedding facts for " << sectionName << " with original size "
    // << facts.size() << " and compressed size " << compressedFacts.size() <<
    // "\n";

    Constant *dataArr = ConstantDataArray::get(C, compressedFacts);
    GlobalVariable *gv =
        new GlobalVariable(M, dataArr->getType(),
                           /*isConstant=*/true, GlobalValue::InternalLinkage,
                           dataArr, "resolve" + std::string(sectionName));
    gv->setAlignment(Align());
    gv->setSection(sectionName);
    appendToCompilerUsed(M, {gv});
  };

  embedFactsSection(".facts", facts);
}
