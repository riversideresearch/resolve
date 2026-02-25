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

#include "json/json.hpp"

#include "resolve_facts/resolve_facts.hpp"

using NamespacedNodeId = resolve_facts::NamespacedNodeId;

template<typename T>
using NodeMap = resolve_facts::NodeMap<T>;

using NodeType = resolve_facts::NodeType;
using Linkage = resolve_facts::Linkage;
using CallType = resolve_facts::CallType;

namespace reach_facts {

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

  struct database {
    NodeMap<NodeType> node_type;
    NodeMap<std::vector<NamespacedNodeId>> contains;
    NodeMap<NamespacedNodeId> calls;
    NodeMap<NamespacedNodeId> function_entrypoints;
    NodeMap<std::vector<NamespacedNodeId>> control_flow;

    NodeMap<std::string> name;
    NodeMap<Linkage> linkage;
    NodeMap<CallType> call_type;
    NodeMap<std::string> fun_sig; // id -> type sig as string
    std::vector<NamespacedNodeId> address_taken;
  };

  database load(std::istream& facts,
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
    bool operator==(const loaded_symbol& rhs) const {
      return symbol == rhs.symbol && library == rhs.library;
    };
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
