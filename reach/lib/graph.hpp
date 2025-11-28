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

using NNodeId = resolve_facts::NamespacedNodeId;

namespace graph {

  // Weight assigned to indirect calls. The default weight for other
  // edges is 1.0.
  constexpr double INDIRECT_WEIGHT = 1000000.0;

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
    NNodeId node;  // the node connected by this edge
    double weight;
    EdgeType type;
    bool operator==(const edge&) const = default;
  };

  double path_weight(const std::vector<edge>& path);

  using E = resolve_facts::NodeMap<std::unordered_set<edge>>;

  // Directed graph
  struct T {
    E edges;
    void addEdge(NNodeId l, NNodeId r, EdgeType ety, double weight);
    inline void addEdge(NNodeId l, NNodeId r, EdgeType ety) {
      this->addEdge(l, r, ety, 1.0); // default weight 1.0.
    }
  };

  // Check that a graph is well-formed (currently just that there are
  // no duplicate nodes in edge lists).
  bool wf(const E& g);

  T build_from_program_facts(const resolve_facts::ProgramFacts& pf, bool dynlink, const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr reach_facts::LoadOptions SIMPLE_LOAD_OPTIONS  =
    reach_facts::LoadOptions::Contains | reach_facts::LoadOptions::Calls
    | reach_facts::LoadOptions::Name | reach_facts::LoadOptions::Linkage
    | reach_facts::LoadOptions::CallType | reach_facts::LoadOptions::AddressTaken
    | reach_facts::LoadOptions::FunctionType;

  // Reachability graph with functions, BBs, instructions, and
  // contains and calls edges, but no control flow edges. This is the
  // first thing we did.
  T build_simple_graph(const reach_facts::database& db,
                     bool dynlink,
                     const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr reach_facts::LoadOptions CALL_LOAD_OPTIONS =
    reach_facts::LoadOptions::Contains | reach_facts::LoadOptions::Calls
    | reach_facts::LoadOptions::Name | reach_facts::LoadOptions::Linkage
    | reach_facts::LoadOptions::CallType | reach_facts::LoadOptions::AddressTaken
    | reach_facts::LoadOptions::FunctionType | reach_facts::LoadOptions::NodeType;

  // Call graph with function nodes only.
  T build_call_graph(const reach_facts::database& db,
                   bool dynlink,
                   const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr reach_facts::LoadOptions CFG_LOAD_OPTIONS =
    reach_facts::LoadOptions::NodeType | reach_facts::LoadOptions::Calls
    | reach_facts::LoadOptions::Contains | reach_facts::LoadOptions::ControlFlow
    | reach_facts::LoadOptions::Name | reach_facts::LoadOptions::Linkage
    | reach_facts::LoadOptions::CallType | reach_facts::LoadOptions::AddressTaken
    | reach_facts::LoadOptions::FunctionType;

  // Interprocedural CFG with function and BB nodes.
  T build_cfg(const reach_facts::database& db,
            bool dynlink = false,
            const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});

  // Instruction-level granularity CFG (rather than BBs).
  T build_instr_cfg(const reach_facts::database& db,
                  bool dynlink = false,
                  const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
}  // namespace graph

namespace std {
  template <>
  struct hash<graph::edge> {
    size_t operator()(const graph::edge& e) const {
      size_t h1 = resolve_facts::pair_hash()(e.node);
      size_t h2 = std::hash<double>()(e.weight);
      size_t h3 = std::hash<graph::EdgeType>()(e.type);
      return h1 ^ h2 ^ h3;
    }
  };
}  // namespace std
