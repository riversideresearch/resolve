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

#include "json.hpp"
#include "glaze/glaze.hpp"

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

  using json = nlohmann::json;

  struct Node {
    NodeType kind;
    std::unordered_map<std::string, std::string> props;
  };

  struct ModuleFacts {
    //std::unordered_map<NodeId, Node> nodes;
    std::unordered_map<NodeId, std::string> node_types;
    // the values here could be more structured if desired, matching with the enums
    std::unordered_map<NodeId, std::unordered_map<std::string, std::string>> node_props;
    // Likewise we only know about so many edge types and this could be more restrictive.
    std::unordered_map<std::pair<NodeId, NodeId>, std::vector<std::string>, pair_hash> edge_kinds;

    ModuleFacts() :
        node_types(), node_props(), edge_kinds()
    {}

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ModuleFacts, node_types, node_props, edge_kinds);

    // Note: the library supports serializing as BSON/CBOR 
    // if we want a minimal-friction binary format instead.
    std::string serialize() {
      json obj = *this;
      
      return obj.dump();
    }

    static ModuleFacts deserialize(std::istream& facts) {
      json obj = json::parse(facts);

      return obj.get<ModuleFacts>();
    }
  };

  struct ProgramFacts {
    std::unordered_map<NodeId, ModuleFacts> modules;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ProgramFacts, modules);

    std::string serialize() {

      std::string json = glz::write_json(*this).value_or("error");
      return json;

      /*
      json obj = *this;
      
      return obj.dump();
      */
    }

    static ProgramFacts deserialize(std::istream& facts) {
      // The stream might be multiple ProgramFacts concatenated together,
      // but separated by a newline. Merge them together.

      ProgramFacts pf;

      std::string line;
      auto i = 0;
      while (std::getline(facts, line)) {
        //std::cout << "Line size: " << line.size() << "\n";
        i += line.size();
        ProgramFacts f;
        auto error = glz::read_json(f, line);
        if (error) {
          std::cout << glz::format_error(error, line);
        }
        /*
        json obj = json::parse(line);

        auto f = obj.get<ProgramFacts>();
        */

        pf.modules.merge(f.modules);

        if (f.modules.size() > 0) {
          for (const auto& [k,_]: f.modules) {
            std::cerr << "Duplicate module id in facts: " << k << std::endl;
          }
        }
        /*
        for (const auto& [k,v]: f.modules) {
          if (pf.modules.contains(k)) {
            std::cerr << "Duplicate module id in facts: " << k << std::endl;
          }

          //std::cout << "Found module " << k << std::endl;
          pf.modules.emplace(k, v);
        }
        */
      }

      std::cout << "Found " << pf.modules.size() << " modules with total size " << i << std::endl;

      return pf;
    }
  };

  // Basic node ids are only unique within the context of a compilation Module which has its own NodeId.
  // The full id would then be (ModuleId, NodeId)
  using NamespacedNodeId = std::pair<NodeId, NodeId>;

  std::string to_string(const NamespacedNodeId& id);

  template<typename V>
  using NodeMap = std::unordered_map<NamespacedNodeId, V, pair_hash>;

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


template <>
struct glz::meta<ReachFacts::ModuleFacts> {
  using T = ReachFacts::ModuleFacts;
  static constexpr auto value = object(
      "node_types", &T::node_types,
      "node_props", &T::node_props,
      "edge_kinds", &T::edge_kinds
  );
};



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
