#pragma once

#include "facts.hpp"

namespace graph {

  // Weight assigned to indirect calls. The default weight for other
  // edges is 1.0.
  constexpr double INDIRECT_WEIGHT = 1000000.0;

  // Bidirectional mapping between node ids and integer handles (keys).
  struct handle_map {
    size_t getHandle(const std::string& id);
    size_t getHandleConst(const std::string& id) const;
    std::optional<size_t> getHandleOpt(const std::string& id) const;
    std::string getId(size_t handle) const;
  private:
    std::vector<std::string> handle2id;
    std::unordered_map<std::string, size_t> id2handle;
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
    size_t node; // the node connected by this edge
    double weight;
    EdgeType type;
    bool operator==(const edge&) const = default;
  };

  double path_weight(const std::vector<edge>& path);

  using E = std::vector<std::vector<edge>>;

  // Directed graph
  struct T {
    E edges;
    void addEdge(size_t l, size_t r, EdgeType ety); // default weight 1.0.
    void addEdge(size_t l, size_t r, EdgeType ety, double weight);
  };

  // Check that a graph is well-formed (currently just that there are
  // no duplicate nodes in edge lists).
  bool wf(const E& g);

  constexpr facts::LoadOptions SIMPLE_LOAD_OPTIONS  =
    facts::LoadOptions::Contains | facts::LoadOptions::Calls
    | facts::LoadOptions::Name | facts::LoadOptions::Linkage
    | facts::LoadOptions::CallType | facts::LoadOptions::AddressTaken
    | facts::LoadOptions::FunctionType;

  // Reachability graph with functions, BBs, instructions, and
  // contains and calls edges, but no control flow edges. This is the
  // first thing we did.
  std::pair<handle_map, T>
  build_simple_graph(const facts::database& db,
		     bool dynlink,
		     const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr facts::LoadOptions CALL_LOAD_OPTIONS =
    facts::LoadOptions::Contains | facts::LoadOptions::Calls
    | facts::LoadOptions::Name | facts::LoadOptions::Linkage
    | facts::LoadOptions::CallType | facts::LoadOptions::AddressTaken
    | facts::LoadOptions::FunctionType | facts::LoadOptions::NodeType;

  // Call graph with function nodes only.
  std::pair<handle_map, T>
  build_call_graph(const facts::database& db,
		   bool dynlink,
		   const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms);

  constexpr facts::LoadOptions CFG_LOAD_OPTIONS =
    facts::LoadOptions::NodeType | facts::LoadOptions::Calls
    | facts::LoadOptions::Contains | facts::LoadOptions::ControlFlow
    | facts::LoadOptions::Name | facts::LoadOptions::Linkage
    | facts::LoadOptions::CallType | facts::LoadOptions::AddressTaken
    | facts::LoadOptions::FunctionType;

  // Interprocedural CFG with function and BB nodes.
  std::pair<handle_map, T>
  build_cfg(const facts::database& db,
	    bool dynlink = false,
	    const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});

  // Instruction-level granularity CFG (rather than BBs).
  std::pair<handle_map, T>
  build_instr_cfg(const facts::database& db,
		  bool dynlink = false,
		  const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
} // graph

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
}
