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

using namespace resolve_facts;
using namespace reach_facts;
using namespace std;


#define DB_ERR(id, m1, m2) \
  std::cerr << "id " << resolve_facts::to_string(id) << " in " << #m1 << " not found in " << #m2 << std::endl

namespace fs = filesystem;

database reach_facts::load(istream& facts,
                     LoadOptions options) {
  database db;
  auto pf = ProgramFacts::deserialize(facts);


  auto num_nodes = 0;
  for (const auto& [k,v]: pf.modules) {
      num_nodes += v.nodes.size();
  }

  db.node_type.reserve(num_nodes);
  db.name.reserve(num_nodes);

  for (const auto& [mid, m]: pf.modules) {

    for (const auto& [nid, n]: m.nodes) {
      auto id = std::make_pair(mid, nid);
      if (is_set(options, LoadOptions::NodeType)) {
        db.node_type.emplace(id, n.type);
      }

      if (is_set(options, LoadOptions::NodeProps)) {
        if (is_set(options, LoadOptions::Name) && n.name.has_value()) {
          db.name.emplace(id, *n.name);
        }
        if (is_set(options, LoadOptions::Linkage) && n.linkage.has_value()) {
          db.linkage.emplace(id, *n.linkage);
        }
        if (is_set(options, LoadOptions::CallType) && n.call_type.has_value()) {
          db.call_type.emplace(id, *n.call_type);
        }
        if (is_set(options, LoadOptions::AddressTaken) && n.address_taken == true) {
           db.address_taken.push_back(id);
        } 
        if (is_set(options, LoadOptions::FunctionType) && n.function_type.has_value()) {
          auto ft = *n.function_type;
          db.fun_sig.emplace(id, ft.substr(1, ft.length()-2));
        }
      }
    }

    if (is_set(options, LoadOptions::Edges)) {
      for (const auto& [eid, e]: m.edges) {
        const auto& [s, d] = eid;
        auto sid = std::make_pair(mid, s);
        auto did = std::make_pair(mid, d);
        for (const auto k: e.kinds) {
          if (is_set(options, LoadOptions::Contains) && k == EdgeKind::Contains) {
            db.contains[sid].push_back(did);
          } else if (is_set(options, LoadOptions::Calls) && k == EdgeKind::Calls) {
            db.calls.emplace(sid, did);
          } else if (is_set(options, LoadOptions::ControlFlow) &&
                     k == EdgeKind::ControlFlowTo) {
            db.control_flow[sid].push_back(did);
          } else if (k == EdgeKind::EntryPoint) {
            db.function_entrypoints[sid] = did;
          }
        }
      }
    }
  }

  return db;
}

database reach_facts::load(const fs::path& facts_dir, LoadOptions options) {
  const string facts_path = facts_dir / "facts.facts";
  ifstream facts(facts_path);

  if (!facts.is_open()) {
    throw runtime_error("Failed to open: " + facts_path);
  }

  return load(facts, options);
}

// These checks ensure that the hashmap lookups in
// graph::build_call_graph and graph::build_cfg will succeed.
bool reach_facts::validate(const database& db) {
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
        std::cerr << "Basic block with id " << resolve_facts::to_string(id)
                  << " not found in db.contains" << std::endl;
        return false;
      }
    }
  }

  return true;
}
