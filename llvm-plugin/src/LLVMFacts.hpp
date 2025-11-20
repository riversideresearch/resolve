/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_LLVMFACTS_HPP
#define RESOLVE_LLVM_LLVMFACTS_HPP

#include "Facts.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"

#include <unordered_map>

using NodeId = ReachFacts::NodeId;

class LLVMFacts {
  Facts &facts;
  NodeId next_node_id = 1;

  std::unordered_map<const llvm::Module *, NodeId> moduleIDs;
  std::unordered_map<const llvm::Function *, NodeId> functionIDs;
  std::unordered_map<const llvm::BasicBlock *, NodeId> basicBlockIDs;
  std::unordered_map<const llvm::Argument *, NodeId> argumentIDs;
  std::unordered_map<const llvm::Instruction *, NodeId> instructionIDs;
  std::unordered_map<const llvm::GlobalVariable *, NodeId> globalVarIDs;

  /*
  using edge_rec_t = std::tuple<std::string, NodeId, NodeId>;
  struct edge_rec_hash : public std::function<std::size_t(edge_rec_t)> {
    std::hash<std::string> hasher;
    std::size_t operator()(const edge_rec_t &k) const {
      return hasher(std::get<0>(k)) ^ hasher(std::get<1>(k)) ^
             hasher(std::get<2>(k));
    }

    edge_rec_hash() {}
  };
  std::unordered_map<edge_rec_t, std::size_t, edge_rec_hash> edgeIdx;
  */

public:
  LLVMFacts(Facts &facts)
      : facts(facts) {
  }

  NodeId addNode(const llvm::Module &M) {
    if (moduleIDs.find(&M) == moduleIDs.end()) {

      llvm::SmallString<128> src_path = llvm::StringRef(M.getSourceFileName());
      llvm::sys::fs::make_absolute(src_path);

      std::string src = (std::string)src_path;
      size_t hash = std::hash<std::string>{}(src);
      auto id = 0; //(NodeId) hash;

      llvm::errs() << "Creating new module: " << id << "\n";

      moduleIDs[&M] = id;

      facts.recordNode(id, "Module");
      return id;
    }
    return moduleIDs[&M];
  }

  template<typename T>
  NodeId getModuleId(const T& i) {
      const llvm::Module* module;
      constexpr bool parent_is_module = std::is_same_v<decltype(i.getParent()), const llvm::Module*>;
      constexpr bool is_argument = std::is_same_v<T, llvm::Argument>;
      if constexpr (parent_is_module) {
          module = i.getParent();
      } else if constexpr (is_argument) {
          module = i.getParent()->getParent();
      } else {
          module = i.getModule();
      }

      assert(module);
      return addNode(*module);
  }

  template <typename T> static std::size_t getIndexInParent(const T &item) {
    const auto &parent = *item.getParent();
    return std::distance(parent.begin(), item.getIterator());
  }

  NodeId addNode(const llvm::GlobalVariable &GV) {
    if (globalVarIDs.find(&GV) == globalVarIDs.end()) {
      auto id = next_node_id;
      next_node_id += 1;
      auto module_id = getModuleId(GV);

      globalVarIDs[&GV] = id;
      facts.recordNode(id, "GlobalVariable");
      return id;
    }
    return globalVarIDs[&GV];
  }

  NodeId addNode(const llvm::Function &F) {
    if (functionIDs.find(&F) == functionIDs.end()) {
      auto id = next_node_id;
      next_node_id += 1;
      auto module_id = getModuleId(F);

      functionIDs[&F] = id;
      facts.recordNode(id, "Function");
      return id;
    }
    return functionIDs[&F];
  }

  NodeId addNode(const llvm::Argument &A) {
    if (argumentIDs.find(&A) == argumentIDs.end()) {
      auto id = next_node_id;
      next_node_id += 1;
      auto module_id = getModuleId(A);

      argumentIDs[&A] = id;
      facts.recordNode(id, "Argument");
      return id;
    }
    return argumentIDs[&A];
  }

  NodeId addNode(const llvm::BasicBlock &BB) {
    if (basicBlockIDs.find(&BB) == basicBlockIDs.end()) {
      auto id = next_node_id;
      next_node_id += 1;
      auto module_id = getModuleId(BB);

      basicBlockIDs[&BB] = id;
      facts.recordNode(id, "BasicBlock");
      return id;
    }
    return basicBlockIDs[&BB];
  }

  NodeId addNode(const llvm::Instruction &I) {
    if (instructionIDs.find(&I) == instructionIDs.end()) {
      auto id = next_node_id;
      next_node_id += 1;
      auto module_id = getModuleId(I);

      instructionIDs[&I] = id;
      facts.recordNode(id, "Instruction");
      return id;
    }
    return instructionIDs[&I];
  }

  template <typename S, typename D>
  void addEdge(std::string kind, S &src, D &dst) {
    addEdge(kind, addNode(src), addNode(dst));
  }

  void addEdge(std::string kind, NodeId src, NodeId dst) {
    facts.recordEdge(kind, src, dst);
  }

  template <typename N>
  void addNodeProp(const N &node, const std::string &key,
                   const std::string &value) {
    facts.recordNodeProp(addNode(node), key, value);
  }

  const std::string serialize() const { 
      auto nodes = facts.bf.node_types.size();
      auto node_props = facts.bf.node_props.size();
      auto edges = facts.bf.edge_kinds.size();

      llvm::errs() << "Created " << nodes << " nodes, " << node_props << " node props, and " << edges << "edges\n";

      return facts.bf.serialize();
  }

  /*
  const std::string &getNodes() const { return facts.nodes; }

  const std::string &getNodeProps() const { return facts.nodeProps; }

  const std::string &getEdges() const { return facts.edges; }

  const std::string &getEdgeProps() const { return facts.edgeProps; }
  */
};

#endif // RESOLVE_LLVM_LLVMFACTS_HPP
