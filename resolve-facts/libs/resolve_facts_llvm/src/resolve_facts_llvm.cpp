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

using namespace llvm;

using Linkage = resolve_facts::Linkage;
using CallType = resolve_facts::CallType;
using EdgeKind = resolve_facts::EdgeKind;

std::string resolve::debugLocToString(DebugLoc dbgLoc) {
  auto line = std::to_string(dbgLoc.getLine());
  auto col = std::to_string(dbgLoc.getCol());
  return line + ":" + col;
}

std::string resolve::typeToString(const Type &type) {
  std::string str;
  llvm::raw_string_ostream out(str);
  type.print(out);
  return str;
}

void resolve::getGlobalFacts(GlobalVariable &G) {
  facts.addNode(G);
  facts.addNodeProp(G, [&](auto& node) {
    node.name = G.getName().str();
    node.linkage = (G.hasExternalLinkage() ? Linkage::ExternalLinkage : Linkage::Other);
  });
}

void resolve::getFunctionFacts(Function &F) {
  facts.addNode(F);
  facts.addNodeProp(F, [&](auto& node) {
    node.name = F.getName().str();
    node.linkage = (F.hasExternalLinkage() ? Linkage::ExternalLinkage : Linkage::Other);
    node.function_type = typeToString(*F.getFunctionType());
    if (F.hasAddressTaken()) {
      node.address_taken = true;
    }
  });

  if (F.isDeclaration())
    return;

  facts.addEdge(F, F.getEntryBlock(), [](auto& edge) { edge.kinds.push_back(EdgeKind::EntryPoint); });

  for (Argument &A : F.args()) {
    facts.addEdge(F, A, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Contains); });
    facts.addNodeProp(A, [&](auto& node) { node.idx = A.getArgNo(); });
  }

  for (BasicBlock &BB : F) {
    facts.addEdge(F, BB, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Contains); });
    facts.addNodeProp(BB, [&](auto& node) { 
      node.idx = LLVMFacts::getIndexInParent(BB);
      if (BB.hasName()) {
        node.name = BB.getName().str();
      }
    });

    // Control flow Edges
    for (BasicBlock *Succ : successors(&BB)) {
      facts.addEdge(BB, *Succ, [&](auto& edge) { edge.kinds.push_back(EdgeKind::ControlFlowTo); });
    }

    for (Instruction &I : BB) {
      facts.addEdge(BB, I, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Contains); });
      facts.addNodeProp(I, [&](auto& node) {
        node.opcode = I.getOpcodeName();
        if (auto dbgLoc = I.getDebugLoc()) {
           node.source_loc = debugLocToString(dbgLoc);
        }
      });

      // Data–flow edges: from each operand (if an instruction) to I.
      for (Value *op : I.operands()) {
        if (Instruction *opI = dyn_cast<Instruction>(op)) {
          facts.addEdge(*opI, I, [&](auto& edge) { edge.kinds.push_back(EdgeKind::DataFlowTo); });
        } else if (Argument *opA = dyn_cast<Argument>(op)) {
          facts.addEdge(*opA, I, [&](auto& edge) { edge.kinds.push_back(EdgeKind::DataFlowTo); });
        } else if (GlobalVariable *opG = dyn_cast<GlobalVariable>(op)) {
          facts.addEdge(I, *opG, [&](auto& edge) { edge.kinds.push_back(EdgeKind::References); });
        } else if (Function *opF = dyn_cast<Function>(op)) {
          facts.addEdge(I, *opF, [&](auto& edge) { edge.kinds.push_back(EdgeKind::References); });
        }
      }

      // Call edge: record call relationship at the instruction level only.
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        CallType ct;
        if (Function *Callee = CB->getCalledFunction()) {
          facts.addEdge(I, *Callee, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Calls); });
          ct = CallType::Direct;
        } else {
          // Indirect call
          ct = CallType::Indirect;
        }

        facts.addNodeProp(I, [&](auto& node) {
            node.call_type = ct;
            node.function_type = typeToString(*CB->getFunctionType());
        });
      }
    }
  }
}

void resolve::getModuleFacts(Module &M) {
  facts.addNodeProp(M, [&](auto& node) { node.source_file = M.getSourceFileName(); });

  for (GlobalVariable &G : M.globals()) {
    facts.addEdge(M, G, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Contains); });

    getGlobalFacts(G);
  }

  for (Function &F : M) {
    facts.addEdge(M, F, [&](auto& edge) { edge.kinds.push_back(EdgeKind::Contains); });

    getFunctionFacts(F);
  }
}

// Embed the accumulated facts into custom ELF sections.
void resolve::embedFacts(Module &M) {
  LLVMContext &C = M.getContext();
  auto embedFactsSection = [&](StringRef sectionName,
                               const std::string &facts) {
    ArrayRef<uint8_t> inputData(reinterpret_cast<const uint8_t *>(facts.data()),
                                facts.size());
    SmallVector<uint8_t> compressedFacts;

    if (std::getenv("RESOLVE_IGNORE_COMPRESSION")) {
      compressedFacts = SmallVector<uint8_t>(inputData);
    } else {
      compression::Params params(compression::Format::Zstd);
      compression::compress(params, inputData, compressedFacts);
    }

    //errs() << "Embedding facts for " << sectionName << " with original size " << facts.size() << " and compressed size " << compressedFacts.size() << "\n";

    Constant *dataArr = ConstantDataArray::get(C, compressedFacts);
    GlobalVariable *gv =
        new GlobalVariable(M, dataArr->getType(),
                           /*isConstant=*/true, GlobalValue::InternalLinkage,
                           dataArr, "resolve" + std::string(sectionName));
    gv->setAlignment(Align());
    gv->setSection(sectionName);
    appendToCompilerUsed(M, {gv});
  };

  // add a newline afterwards to help-distinguish between combined modules
  embedFactsSection(".facts", facts.serialize() + "\n");
}
