/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_FACTS_HPP
#define RESOLVE_LLVM_FACTS_HPP

#include <string>
#include <unordered_map>

#include "facts.hpp"

using ProgramFacts = ReachFacts::ProgramFacts;
using ModuleFacts = ReachFacts::ModuleFacts;
using NodeId = ReachFacts::NodeId;

// A node can be one of {Module, GlobalValue, Function, Argument, BasicBlock, Instruction, ...}
// Each node must have some id.
// A node can have a set of properties associated with it, e.g. a unordered_map<string, string>
// Nodes can be connected by "edges" of a particular kind. Currently these edges can have multiplicity. e.g. ("Contains", node1, node2) is an edge

struct Facts {
  ProgramFacts pf;

  void recordNewModule(const NodeId& id, const size_t size_hint) {
      ModuleFacts mf{};
      // Try to avoid reallocations
      mf.node_props.reserve(size_hint);
      mf.node_types.reserve(size_hint);
      mf.edge_kinds.reserve(2*size_hint);

      pf.modules[id] = mf;
  }

  /// Record a node fact.
  void recordNode(const NodeId& module, const NodeId& id, const std::string &type) {
    pf.modules.at(module).node_types.emplace(id, type);
  }

  /// Record a node property.
  void recordNodeProp(const NodeId& module, const NodeId& nodeID, const std::string &key,
                      const std::string &value) {
    auto& mf = pf.modules.at(module);
    auto [it, exists] = mf.node_props.try_emplace(nodeID);
    it->second[key] = value;
  }

  /// Record an edge fact.
  void recordEdge(const NodeId& module, const std::string &type,
                  const NodeId &srcID, const NodeId &tgtID) {
    auto pair = std::make_pair(srcID, tgtID);
    auto& mf = pf.modules.at(module);
    auto [it, exists] = mf.edge_kinds.try_emplace(pair);
    it->second.emplace_back(type);
  }
};

#endif // RESOLVE_LLVM_FACTS_HPP
