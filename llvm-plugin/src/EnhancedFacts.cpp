// EnhancedFacts.cpp

#include "Facts.hpp"
#include "LLVMFacts.hpp"
#include "NodeID.hpp"

#include <cstdlib> // For std::getenv
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Compression.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static Facts all_facts;

static LLVMFacts facts(all_facts, std::getenv("GlobalContext") ?: "");

static std::string debugLocToString(DebugLoc dbgLoc) {
  auto line = std::to_string(dbgLoc.getLine());
  auto col = std::to_string(dbgLoc.getCol());
  return line + ":" + col;
}

static std::string typeToString(const Type &type) {
  std::string str;
  llvm::raw_string_ostream out(str);
  type.print(out);
  return "\"" + str + "\"";
}

static void getGlobalFacts(GlobalVariable &G) {
  facts.addNode(G);
  facts.addNodeProp(G, "name", G.getName().str());
  facts.addNodeProp(G, "linkage",
                    (G.hasExternalLinkage() ? "ExternalLinkage" : "Other"));

  // for (Value *op : G.operands()) {
  //     if (Instruction *opI = dyn_cast<Instruction>(op)) {
  //         std::string opID = getInstructionID(*opI, prefix);
  //         std::string edgeID = make_edge_id(prefix);
  //         recordEdge(edgeID, "dataFlowTo", opID, iID);
  //     } else if (GlobalVariable *opG = dyn_cast<GlobalVariable>(op)) {
  //         std::string opGID = getGlobalVarID(*opG, prefix);
  //         std::string edgeID = make_edge_id(prefix);
  //         recordEdge(edgeID, "references", iID, opGID);
  //     } else if (Function *opF = dyn_cast<Function>(op)) {
  //         std::string opFID = getFunctionID(*opF, prefix);
  //         std::string edgeID = make_edge_id(prefix);
  //         recordEdge(edgeID, "references", iID, opFID);
  //     }
  // }
}

static void getFunctionFacts(Function &F) {
  facts.addNode(F);
  facts.addNodeProp(F, "name", F.getName().str());
  facts.addNodeProp(F, "linkage",
                    (F.hasExternalLinkage() ? "ExternalLinkage" : "Other"));
  facts.addNodeProp(F, "function_type", typeToString(*F.getFunctionType()));

  if (F.hasAddressTaken()) {
    facts.addNodeProp(F, "address_taken", "");
  }

  if (F.isDeclaration())
    return;

  facts.addEdge("entryPoint", F, F.getEntryBlock());

  for (Argument &A : F.args()) {
    facts.addEdge("contains", F, A);
    facts.addNodeProp(A, "idx", std::to_string(A.getArgNo()));
  }

  for (BasicBlock &BB : F) {
    facts.addEdge("contains", F, BB);
    facts.addNodeProp(BB, "idx",
                      std::to_string(LLVMFacts::getIndexInParent(BB)));
    if (BB.hasName())
      facts.addNodeProp(BB, "label", BB.getName().str());

    // Control flow Edges
    for (BasicBlock *Succ : successors(&BB)) {
      facts.addEdge("controlFlowTo", BB, *Succ);
    }

    for (Instruction &I : BB) {
      facts.addEdge("contains", BB, I);
      facts.addNodeProp(I, "opcode", I.getOpcodeName());
      if (auto dbgLoc = I.getDebugLoc()) {
        facts.addNodeProp(I, "source_loc", debugLocToString(dbgLoc));
      }

      // Data–flow edges: from each operand (if an instruction) to I.
      for (Value *op : I.operands()) {
        if (Instruction *opI = dyn_cast<Instruction>(op)) {
          facts.addEdge("dataFlowTo", *opI, I);
        } else if (Argument *opA = dyn_cast<Argument>(op)) {
          facts.addEdge("dataFlowTo", *opA, I);
        } else if (GlobalVariable *opG = dyn_cast<GlobalVariable>(op)) {
          facts.addEdge("references", I, *opG);
        } else if (Function *opF = dyn_cast<Function>(op)) {
          facts.addEdge("references", I, *opF);
        }
      }

      // Call edge: record call relationship at the instruction level only.
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (Function *Callee = CB->getCalledFunction()) {
          facts.addEdge("calls", I, *Callee);
          facts.addNodeProp(I, "call_type", "direct");
        } else {
          // Indirect call
          facts.addNodeProp(I, "call_type", "indirect");
        }
        facts.addNodeProp(I, "function_type",
                          typeToString(*CB->getFunctionType()));
      }
    }
  }
}

static void getModuleFacts(Module &M) {
  facts.addNodeProp(M, "source_file", M.getSourceFileName());

  for (GlobalVariable &G : M.globals()) {
    facts.addEdge("contains", M, G);

    getGlobalFacts(G);
  }

  for (Function &F : M) {
    facts.addEdge("contains", M, F);

    getFunctionFacts(F);
  }
}

// Embed the accumulated facts into custom ELF sections.
static void embedFacts(Module &M) {
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

    Constant *dataArr = ConstantDataArray::get(C, compressedFacts);
    GlobalVariable *gv =
        new GlobalVariable(M, dataArr->getType(),
                           /*isConstant=*/true, GlobalValue::InternalLinkage,
                           dataArr, "resolve" + std::string(sectionName));
    gv->setAlignment(Align());
    gv->setSection(sectionName);
    appendToCompilerUsed(M, {gv});
  };

  embedFactsSection(".fact_nodes", facts.getNodes());
  embedFactsSection(".fact_node_props", facts.getNodeProps());
  embedFactsSection(".fact_edges", facts.getEdges());
  embedFactsSection(".fact_edge_props", facts.getEdgeProps());
}

struct EnhancedFactsPass : public PassInfoMixin<EnhancedFactsPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    getModuleFacts(M);
    embedFacts(M);
    return PreservedAnalyses::all();
  }
};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "EnhancedFacts", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [&](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(EnhancedFactsPass());
                });
          }};
}
