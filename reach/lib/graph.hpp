/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <utility>
#include <unordered_set>
#include <vector>

#include "facts.hpp"

using NNodeId = ReachFacts::NamespacedNodeId;

namespace graph {

  // Weight assigned to indirect calls. The default weight for other
  // edges is 1.0.
  constexpr double INDIRECT_WEIGHT = 1000000.0;

  // Bidirectional mapping between node ids and integer handles (keys).
  struct handle_map {
    size_t getHandle(const NNodeId& id);
    size_t getHandleConst(const NNodeId& id) const;
    std::optional<size_t> getHandleOpt(const NNodeId& id) const;
    NNodeId getId(size_t handle) const;
   private:
    std::vector<NNodeId> handle2id;
    ReachFacts::NodeMap<size_t> id2handle;
    void build_id2handle();
  };

  enum class EdgeType {
    DirectCall,
    IndirectCall,
    Contains,
    Succ,
    Extern,
    ExternIndirectCall,
    Self
  };

  std::string EdgeType_to_string(EdgeType ety);

  struct edge {
    size_t node;  // the node connected by this edge
    double weight;
    EdgeType type;
    bool operator==(const edge&) const = default;
  };

  double path_weight(const std::vector<edge>& path);

  using E = std::vector<std::unordered_set<edge>>;

  // Directed graph
  struct T {
    E edges;
    void addEdge(size_t l, size_t r, EdgeType ety, double weight);
    inline void addEdge(size_t l, size_t r, EdgeType ety) {
      this->addEdge(l, r, ety, 1.0); // default weight 1.0.
    }
  };

  // Check that a graph is well-formed (currently just that there are
  // no duplicate nodes in edge lists).
  bool wf(const E& g);

  constexpr ReachFacts::LoadOptions SIMPLE_LOAD_OPTIONS  =
    ReachFacts::LoadOptions::Contains | ReachFacts::LoadOptions::Calls
    | ReachFacts::LoadOptions::Name | ReachFacts::LoadOptions::Linkage
    | ReachFacts::LoadOptions::CallType | ReachFacts::LoadOptions::AddressTaken
    | ReachFacts::LoadOptions::FunctionType;

  // Reachability graph with functions, BBs, instructions, and
  // contains and calls edges, but no control flow edges. This is the
  // first thing we did.
  std::pair<handle_map, T>
  build_simple_graph(const ReachFacts::database& db,
                     bool dynlink,
                     const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr ReachFacts::LoadOptions CALL_LOAD_OPTIONS =
    ReachFacts::LoadOptions::Contains | ReachFacts::LoadOptions::Calls
    | ReachFacts::LoadOptions::Name | ReachFacts::LoadOptions::Linkage
    | ReachFacts::LoadOptions::CallType | ReachFacts::LoadOptions::AddressTaken
    | ReachFacts::LoadOptions::FunctionType | ReachFacts::LoadOptions::NodeType;

  // Call graph with function nodes only.
  std::pair<handle_map, T>
  build_call_graph(const ReachFacts::database& db,
                   bool dynlink,
                   const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr ReachFacts::LoadOptions CFG_LOAD_OPTIONS =
    ReachFacts::LoadOptions::NodeType | ReachFacts::LoadOptions::Calls
    | ReachFacts::LoadOptions::Contains | ReachFacts::LoadOptions::ControlFlow
    | ReachFacts::LoadOptions::Name | ReachFacts::LoadOptions::Linkage
    | ReachFacts::LoadOptions::CallType | ReachFacts::LoadOptions::AddressTaken
    | ReachFacts::LoadOptions::FunctionType;

  // Interprocedural CFG with function and BB nodes.
  std::pair<handle_map, T>
  build_cfg(const ReachFacts::database& db,
            bool dynlink = false,
            const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});

  // Instruction-level granularity CFG (rather than BBs).
  std::pair<handle_map, T>
  build_instr_cfg(const ReachFacts::database& db,
                  bool dynlink = false,
                  const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
}  // namespace graph

namespace std {
  template <>
  struct hash<graph::edge> {
    size_t operator()(const graph::edge& e) const {
      size_t h1 = std::hash<size_t>()(e.node);
      size_t h2 = std::hash<double>()(e.weight);
      size_t h3 = std::hash<graph::EdgeType>()(e.type);
      return h1 ^ h2 ^ h3;
    }
  };
}  // namespace std
