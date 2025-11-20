/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_FACTS_HPP
#define RESOLVE_LLVM_FACTS_HPP

#include <string>
#include <unordered_map>

#include "facts.hpp"

using ModuleFacts = ReachFacts::ModuleFacts;
using NodeId = ReachFacts::NodeId;

// A node can be one of {Module, GlobalValue, Function, Argument, BasicBlock, Instruction, ...}
// Each node must have some id.
// A node can have a set of properties associated with it, e.g. a unordered_map<string, string>
// Nodes can be connected by "edges" of a particular kind. Currently these edges can have multiplicity. e.g. ("Contains", node1, node2) is an edge

struct Facts {
  ModuleFacts bf;

  /// Record a node fact.
  void recordNode(const NodeId& id, const std::string &type) {
    bf.node_types.emplace(id, type);
  }

  /// Record a node property.
  void recordNodeProp(const NodeId& nodeID, const std::string &key,
                      const std::string &value) {
    if (bf.node_props.contains(nodeID)) {
        bf.node_props[nodeID][key] = value;
    } else {
        std::unordered_map<std::string, std::string> new_map = { std::make_pair(key, value) };
        bf.node_props.try_emplace(nodeID, new_map);
    }
  }

  /// Record an edge fact.
  void recordEdge(const std::string &type,
                  const NodeId &srcID, const NodeId &tgtID) {
    auto pair = std::make_pair(srcID, tgtID);
    if (bf.edge_kinds.contains(pair)) {
      bf.edge_kinds[pair].emplace_back(type);
    } else {
        std::vector<std::string> new_kinds = {type};
        bf.edge_kinds[pair] = new_kinds;
    }
  }
};

#endif // RESOLVE_LLVM_FACTS_HPP
