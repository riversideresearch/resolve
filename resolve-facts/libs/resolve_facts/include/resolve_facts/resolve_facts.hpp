/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <optional>
#include <functional>

namespace resolve_facts {

  enum class NodeType {
    Module,
    GlobalVariable,
    Function,
    Argument,
    BasicBlock,
    Instruction,
  };

  enum class Linkage {
    ExternalLinkage,
    Other,
  };

  enum class CallType {
    Direct,
    Indirect,
  };

  // Type synonym for node NodeIds.
  using NodeId = uint32_t;

  struct pair_hash : public std::function<std::size_t(std::pair<NodeId, NodeId>)> {
    std::hash<uint64_t> hasher;
    std::size_t operator()(const std::pair<NodeId, NodeId> &k) const {
      // Hash as a single uint64_t because hashing as two individual uint32_t ended up being hilariously slow
      // which could have also just been a side effect of being a poor hash combiner.
      uint64_t s = ((uint64_t)k.first) << 32 | (uint64_t)k.second;
      return hasher(s);
    }

    pair_hash() {}
  };


  struct Node {
    NodeType type;
    std::optional<std::string> name;
    std::optional<Linkage> linkage;
    std::optional<CallType> call_type;
    std::optional<uint32_t> idx;
    std::optional<std::string> function_type;
    std::optional<bool> address_taken;
    std::optional<std::string> opcode;
    std::optional<std::string> source_file;
    std::optional<std::string> source_loc;
  };

  enum class EdgeKind {
    Contains,
    Calls,
    References,
    EntryPoint,
    ControlFlowTo,
    DataFlowTo,
  };

  struct Edge {
    std::vector<EdgeKind> kinds;
  };

  struct EdgeId {
    NodeId first;
    NodeId second;
    EdgeId() = default;
    EdgeId(NodeId first, NodeId second): first(first), second(second) {}
    bool operator==(const EdgeId& o) const {
      return first == o.first && second == o.second;
    }
  };

  struct e_hash : public std::function<std::size_t(const EdgeId&)> {
    std::hash<uint64_t> hasher;
    std::size_t operator()(const EdgeId &e) const {
      // Hash as a single uint64_t because hashing as two individual uint32_t ended up being hilariously slow
      // which could have also just been a side effect of being a poor hash combiner.
      uint64_t s = ((uint64_t)e.first) << 32 | (uint64_t)e.second;
      return hasher(s);
    }

    e_hash() {}
  };

  struct ModuleFacts {
    std::unordered_map<NodeId, Node> nodes;
    std::unordered_map<EdgeId, Edge, e_hash> edges;

    ModuleFacts() :
      nodes(), edges()
    {}

    std::string serialize() const;
    static ModuleFacts deserialize(std::istream& facts);

  };

  // Basic node ids are only unique within the context of a compilation Module which has its own NodeId.
  // The full id would then be (ModuleId, NodeId)
  using NamespacedNodeId = std::pair<NodeId, NodeId>;

  std::string to_string(const NamespacedNodeId& id);

  struct ProgramFacts {
    std::unordered_map<NodeId, ModuleFacts> modules;

    std::string serialize() const;
    static ProgramFacts deserialize(std::istream& facts);

    const Node& getModuleOfNode(const NamespacedNodeId& nodeId) const;
    bool containsNode(const NamespacedNodeId& nodeId) const;
    const Node& getNode(const NamespacedNodeId& nodeId) const;
  };

  template<typename V>
  using NodeMap = std::unordered_map<NamespacedNodeId, V, pair_hash>;
}  // namespace resolve_facts 
