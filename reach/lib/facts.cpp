/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include "facts.hpp"
#include "util.hpp"

#define DB_ERR(id, m1, m2) \
  std::cerr << "id " << ReachFacts::to_string(id) << " in " << #m1 << " not found in " << #m2 << std::endl

using namespace ReachFacts;
using namespace std;
namespace fs = filesystem;


inline NodeType parse_node_type(const string& s) {
  static unordered_map<string, NodeType> m = {
    { "Module", NodeType::Module },
    { "GlobalVariable", NodeType::GlobalVariable },
    { "Function", NodeType::Function },
    { "Argument", NodeType::Argument },
    { "BasicBlock", NodeType::BasicBlock },
    { "Instruction", NodeType::Instruction },
  };
  return m[s];
}

inline Linkage parse_linkage(const string& s) {
  static unordered_map<string, Linkage> m = {
    { "ExternalLinkage", Linkage::ExternalLinkage },
    { "Other", Linkage::Other },
  };
  return m[s];
}

inline CallType parse_call_type(const string& s) {
  static unordered_map<string, CallType> m = {
    { "direct", CallType::Direct },
    { "indirect", CallType::Indirect },
  };
  return m[s];
}

database ReachFacts::load(istream& facts,
                     LoadOptions options) {
  database db;
  auto pf = ProgramFacts::deserialize(facts);


  auto num_nodes = 0;
  for (const auto& [k,v]: pf.modules) {
      num_nodes += v.node_types.size();
  }

  db.node_type.reserve(num_nodes);
  db.name.reserve(num_nodes);

  for (const auto& [mid, m]: pf.modules) {

    if (is_set(options, LoadOptions::NodeType)) {
      for (const auto& [n, ty]: m.node_types) {
        auto id = std::make_pair(mid, n);
        db.node_type.emplace(id, parse_node_type(ty));
      }
    }

    if (is_set(options, LoadOptions::NodeProps)) {
      for (const auto& [n, props]: m.node_props) {
        auto id = std::make_pair(mid, n);
        for (const auto& [prop, val]: props) {
          if (is_set(options, LoadOptions::Name) && prop == "name") {
            db.name.emplace(id, val);
          } else if (is_set(options, LoadOptions::Linkage) && prop == "linkage") {
            db.linkage.emplace(id, parse_linkage(val));
          } else if (is_set(options, LoadOptions::CallType)
                     && prop == "call_type") {
            db.call_type.emplace(id, parse_call_type(val));
          } else if (is_set(options, LoadOptions::AddressTaken) &&
                    prop == "address_taken") {
             db.address_taken.push_back(id);
          } else if (is_set(options, LoadOptions::FunctionType) &&
                     prop == "function_type") {
            db.fun_sig.emplace(id, val.substr(1, val.length()-2));
          }
        }
      }
    }

    if (is_set(options, LoadOptions::Edges)) {
      for (const auto& [e, kinds]: m.edge_kinds) {
        const auto& [s, d] = e;
        auto sid = std::make_pair(mid, s);
        auto did = std::make_pair(mid, d);
        for (const auto k: kinds) {
          if (is_set(options, LoadOptions::Contains) && k == "contains") {
            db.contains[sid].push_back(did);
          } else if (is_set(options, LoadOptions::Calls) && k == "calls") {
            db.calls.emplace(sid, did);
          } else if (is_set(options, LoadOptions::ControlFlow) &&
                     k == "controlFlowTo") {
            db.control_flow[sid].push_back(did);
          } else if (k == "entryPoint") {
            db.function_entrypoints[sid] = did;
          }
        }
      }
    }
  }

  return db;
}

std::string ReachFacts::to_string(const NamespacedNodeId& id) {
  return "(" + std::to_string(id.first) + "," + std::to_string(id.second) + ")";
}

database ReachFacts::load(const fs::path& facts_dir, LoadOptions options) {
  const string facts_path = facts_dir / "facts.facts";
  ifstream facts(facts_path);

  if (!facts.is_open()) {
    throw runtime_error("Failed to open: " + facts_path);
  }

  return load(facts, options);
}

// These checks ensure that the hashmap lookups in
// graph::build_call_graph and graph::build_cfg will succeed.
bool ReachFacts::validate(const database& db) {
  // All nodes are assigned a type.
  if (!(KEYS_SUBSET(db.contains, db.node_type) &&
        KEYS_SUBSET(db.calls, db.node_type) &&
        KEYS_SUBSET(db.control_flow, db.node_type) &&
        KEYS_SUBSET(db.name, db.node_type) &&
        KEYS_SUBSET(db.linkage, db.node_type) &&
        KEYS_SUBSET(db.call_type, db.node_type) &&
        KEYS_SUBSET(db.fun_sig, db.node_type))) {
    return false;
  }

  // Nodes with Direct call type are in [calls] and [fun_sig].
  for (const auto& [id, call_type] : db.call_type) {
    if (call_type == CallType::Direct) {
      if (!db.calls.contains(id)) {
        DB_ERR(id, db.call_type, db.calls);
        return false;
      }
      if (!db.fun_sig.contains(id)) {
        DB_ERR(id, db.call_type, db.fun_sig);
        return false;
      }
    }
  }

  // Nodes in [address_taken] are in [fun_sig].
  for (const auto &id : db.address_taken) {
    if (!db.fun_sig.contains(id)) {
      DB_ERR(id, db.address_taken, db.fun_sig);
      return false;
    }
  }

  // Functions with external linkage appear in [fun_sig] and [name].
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage &&
        db.node_type.at(id) == NodeType::Function) {
      if (!db.fun_sig.contains(id)) {
        DB_ERR(id, db.linkage, db.fun_sig);
        return false;
      }
      if (!db.name.contains(id)) {
        DB_ERR(id, db.linkage, db.name);
        return false;
      }
    }
  }

  // Basic blocks are in [contains].
  for (const auto& [id, node_type] : db.node_type) {
    if (node_type == NodeType::BasicBlock) {
      if (!db.contains.contains(id)) {
        std::cerr << "Basic block with id " << ReachFacts::to_string(id)
                  << " not found in db.contains" << std::endl;
        return false;
      }
    }
  }

  return true;
}
