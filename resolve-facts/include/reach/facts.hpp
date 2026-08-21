/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <filesystem>
#include <istream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "resolve_facts/resolve_facts.hpp"

using NamespacedNodeId = resolve_facts::NamespacedNodeId;

template <typename T> using NodeMap = resolve_facts::NodeMap<T>;

using NodeType = resolve_facts::NodeType;
using Linkage = resolve_facts::Linkage;
using CallType = resolve_facts::CallType;

namespace facts_rs {
struct FactsBuf;
}

namespace reach_facts {

enum class LoadOptions : int {
  None = 0,
  NodeType = 1 << 0,
  Contains = 1 << 1,
  Calls = 1 << 2,
  ControlFlow = 1 << 3, // includes f->bb entry block edges
  Name = 1 << 4,
  Linkage = 1 << 5,
  CallType = 1 << 6,
  AddressTaken = 1 << 7,
  FunctionType = 1 << 8,

  Edges = Contains | Calls | ControlFlow,
  NodeProps = Name | Linkage | CallType | AddressTaken | FunctionType,
  All = NodeType | Edges | NodeProps,
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

database load(std::istream &facts, LoadOptions options);
database load(const std::filesystem::path &facts_dir, LoadOptions options);

std::vector<NamespacedNodeId>
find_functions_by_name_suffix(const facts_rs::FactsBuf *facts,
                              std::string_view suffix);

bool validate(const database &db);
} // namespace reach_facts

// Loaded symbol logs from dynamic analysis, for pruning
// IndirectExtern edges that aren't seen at runtime.
namespace dlsym {
struct loaded_symbol {
  std::string symbol;
  std::string library;
};

} // namespace dlsym
