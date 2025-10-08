#pragma once

#include <fstream>
#include <unordered_set>

#include "json.hpp"

namespace facts {

  enum class LoadOptions : int {
    None         = 0,
    NodeType     = 1 << 0,
    Contains     = 1 << 1,
    Calls        = 1 << 2,
    ControlFlow  = 1 << 3, // includes f->bb entry block edges
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

  // Type synonym for node IDs.
  using ID = std::string;

  struct database {
    std::unordered_map<ID, NodeType> node_type;

    std::unordered_map<ID, std::vector<ID>> contains;
    std::unordered_map<ID, ID> calls;
    std::unordered_map<ID, std::vector<ID>> control_flow;
    // std::unordered_map<ID, ID> entry_point;

    std::unordered_map<ID, std::string> name;
    std::unordered_map<ID, Linkage> linkage;
    std::unordered_map<ID, CallType> call_type;
    std::vector<ID> address_taken;
    std::unordered_map<ID, std::string> fun_sig; // id -> type sig as string
  };

  database load(std::istream& nodes,
		std::istream& nodeprops,
		std::istream& edges,
		LoadOptions options);
  database load(const std::filesystem::path& facts_dir, LoadOptions options);
}

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

  inline std::optional<log> load_log_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
      return {};
    }
    nlohmann::json j;
    f >> j;
    return j.template get<log>();
  }
} // namespace dlsym
