/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_LLVMFACTS_HPP
#define RESOLVE_LLVM_LLVMFACTS_HPP

#include "resolve_facts.hpp"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"

#include <unordered_map>

using ProgramFacts = resolve_facts::ProgramFacts;
using ModuleFacts = resolve_facts::ModuleFacts;
using Node = resolve_facts::Node;
using NodeId = resolve_facts::NodeId;
using NodeType = resolve_facts::NodeType;

class LLVMFacts {
  ProgramFacts &facts;
  NodeId next_node_id = 1;

  std::unordered_map<const llvm::Module *, NodeId> moduleIDs;
  std::unordered_map<const llvm::Function *, NodeId> functionIDs;
  std::unordered_map<const llvm::BasicBlock *, NodeId> basicBlockIDs;
  std::unordered_map<const llvm::Argument *, NodeId> argumentIDs;
  std::unordered_map<const llvm::Instruction *, NodeId> instructionIDs;
  std::unordered_map<const llvm::GlobalVariable *, NodeId> globalVarIDs;

  void recordNewModule(const NodeId& id, const size_t size_hint) {
      ModuleFacts mf{};
      // Try to avoid reallocations
      mf.nodes.reserve(size_hint);
      mf.edges.reserve(2*size_hint);

      facts.modules[id] = mf;
  }

  /// Record a node fact.
  void recordNode(const NodeId& module, const NodeId& id, const NodeType &type) {
    Node node{ .type=type };
    facts.modules.at(module).nodes.emplace(id, node);
  }

  /// Record a node property.
  template<typename F>
  void recordNodeProp(const NodeId& module, const NodeId& nodeID, F&& update_func) {
    auto& mf = facts.modules.at(module);
    update_func(mf.nodes.at(nodeID));
  }

  /// Record an edge fact.
  template<typename F>
  void recordEdge(const NodeId& module, const NodeId &srcID, const NodeId &tgtID,
                  F&& update_func) {
    auto pair = std::make_pair(srcID, tgtID);
    auto& mf = facts.modules.at(module);
    auto [it, exists] = mf.edges.try_emplace(pair);
    update_func(it->second);
  }

public:
  LLVMFacts(ProgramFacts &facts)
      : facts(facts) {
  }

  NodeId addNode(const llvm::Module &M) {
    if (moduleIDs.find(&M) == moduleIDs.end()) {

      llvm::SmallString<128> src_path = llvm::StringRef(M.getSourceFileName());
      llvm::sys::fs::make_absolute(src_path);

      std::string src = (std::string)src_path;
      size_t hash = std::hash<std::string>{}(src);
      auto id = (NodeId) hash;

      llvm::errs() << "Creating new module: " << id << "\n";

      moduleIDs[&M] = id;

      // Estimate how many total nodes we will be creating to prevent rehashes
      auto instrs = M.getInstructionCount();
      recordNewModule(id, 2*instrs);
      recordNode(id, id, NodeType::Module);
      return id;
    }
    return moduleIDs[&M];
  }

  NodeId getModuleId(const llvm::Module& m) {
      return addNode(m);
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
      recordNode(module_id, id, NodeType::GlobalVariable);
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
      recordNode(module_id, id, NodeType::Function);
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
      recordNode(module_id, id, NodeType::Argument);
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
      recordNode(module_id, id, NodeType::BasicBlock);
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
      recordNode(module_id, id, NodeType::Instruction);
      return id;
    }
    return instructionIDs[&I];
  }

  template <typename S, typename D, typename F>
  void addEdge(S &src, D &dst, F&& update_func) {
    auto m1 = getModuleId(src);
    auto m2 = getModuleId(dst);
    assert(m1 == m2);

    addEdge(m1, addNode(src), addNode(dst), update_func);
  }

  template <typename F>
  void addEdge(NodeId module, NodeId src, NodeId dst, F&& update_func) {
    recordEdge(module, src, dst, update_func);
  }

  template <typename N, typename F>
  void addNodeProp(const N &node, F&& update_func) {
    auto module_id = getModuleId(node);
    recordNodeProp(module_id, addNode(node), update_func);
  }

  const std::string serialize() const { 
      return facts.serialize();
  }
};

#endif // RESOLVE_LLVM_LLVMFACTS_HPP
