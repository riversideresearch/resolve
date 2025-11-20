/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "json.hpp"

namespace ReachFacts {

  enum class LoadOptions : int {
    None         = 0,
    NodeType     = 1 << 0,
    Contains     = 1 << 1,
    Calls        = 1 << 2,
    ControlFlow  = 1 << 3,  // includes f->bb entry block edges
    Name         = 1 << 4,
    Linkage      = 1 << 5,
    CallType     = 1 << 6,
    AddressTaken = 1 << 7,
    FunctionType = 1 << 8,

    Edges     = Contains | Calls | ControlFlow,
    NodeProps = Name | Linkage | CallType | AddressTaken | FunctionType,
    All       = NodeType | Edges | NodeProps,
  };

  constexpr LoadOptions operator|(LoadOptions a, LoadOptions b) {
    return static_cast<LoadOptions>(static_cast<int>(a) | static_cast<int>(b));
  }

  constexpr LoadOptions operator&(LoadOptions a, LoadOptions b) {
    return static_cast<LoadOptions>(static_cast<int>(a) & static_cast<int>(b));
  }

  constexpr bool is_set(LoadOptions value, LoadOptions flags) {
    return (value & flags) != LoadOptions::None;
  }

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
  //using NodeId = std::string;
  using NodeId = uint32_t;

  struct pair_hash : public std::function<std::size_t(std::pair<NodeId, NodeId>)> {
    std::hash<NodeId> hasher;
    std::size_t operator()(const std::pair<NodeId, NodeId> &k) const {
      return hasher(std::get<0>(k)) ^ hasher(std::get<1>(k));
    }

    pair_hash() {}
  };

  struct ModuleFacts {
    std::unordered_map<NodeId, std::string> node_types;
    std::unordered_map<NodeId, std::unordered_map<std::string, std::string>> node_props;
    std::unordered_map<std::pair<NodeId, NodeId>, std::vector<std::string>, pair_hash> edge_kinds;

    using json = nlohmann::json;

    ModuleFacts() :
        node_types(), node_props(), edge_kinds()
    {}


    json as_json() {
      json obj = json::object({});
      obj["node_types"] = node_types;
      obj["node_props"] = node_props;
      obj["edge_kinds"] = edge_kinds;
      return obj;
    }

    std::string serialize() {
      auto obj = as_json();

      return obj.dump();
    }
  };

  // Basic node ids are only unique within the context of a compilation Module which has its own NodeId.
  // The full id would then be (ModuleId, NodeId)
  using NamespacedNodeId = std::pair<NodeId, NodeId>;

  template<typename V>
  using NodeMap = std::unordered_map<NamespacedNodeId, V, pair_hash>;

  struct database {
    NodeMap<NodeType> node_type;
    NodeMap<std::vector<NamespacedNodeId>> contains;
    NodeMap<NamespacedNodeId> calls;
    NodeMap<NamespacedNodeId> function_entrypoints;
    NodeMap<std::vector<NamespacedNodeId>> control_flow;
    // std::unordered_map<NamespacedNodeId, NamespacedNodeId> entry_point;

    NodeMap<std::string> name;
    NodeMap<Linkage> linkage;
    NodeMap<CallType> call_type;
    NodeMap<std::string> fun_sig; // id -> type sig as string
    std::vector<NamespacedNodeId> address_taken;
  };

  database load(std::istream& nodes,
                std::istream& nodeprops,
                std::istream& edges,
                LoadOptions options);
  database load(const std::filesystem::path& facts_dir, LoadOptions options);

  bool validate(const database& db);
}  // namespace facts

// Loaded symbol logs from dynamic analysis, for pruning
// IndirectExtern edges that aren't seen at runtime.
namespace dlsym {
  struct loaded_symbol {
    std::string symbol;
    std::string library;
    bool operator==(const loaded_symbol& rhs) const = default;
  };

  struct log {
    std::vector<loaded_symbol> loaded_symbols;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(loaded_symbol, symbol, library);
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(log, loaded_symbols);

  inline std::optional<log>
  load_log_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
      return {};
    }
    nlohmann::json j;
    f >> j;
    return j.template get<log>();
  }
}  // namespace dlsym
