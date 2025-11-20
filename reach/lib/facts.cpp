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

using namespace facts;
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

database facts::load(istream& nodes,
                     istream& nodeprops,
                     istream& edges,
                     LoadOptions options) {
  database db;

  if (is_set(options, LoadOptions::NodeType)) {
    string line;
    while (getline(nodes, line)) {
      stringstream ss(line);
      string id, ty;
      getline(ss, id, ',');
      getline(ss, ty);
      db.node_type.emplace(id, parse_node_type(ty));
    }
  }

  if (is_set(options, LoadOptions::Edges)) {
    string line;
    while (getline(edges, line)) {
      stringstream ss(line);
      string id, ty, s, t;
      getline(ss, id, ',');
      getline(ss, ty, ',');
      getline(ss, s, ',');
      getline(ss, t);
      if (is_set(options, LoadOptions::Contains) && ty == "contains") {
        db.contains[s].push_back(t);
      } else if (is_set(options, LoadOptions::Calls) && ty == "calls") {
        db.calls.emplace(s, t);
      } else if (is_set(options, LoadOptions::ControlFlow) &&
                 ty == "controlFlowTo") {
        db.control_flow[s].push_back(t);
      }
    }
  }

  if (is_set(options, LoadOptions::NodeProps)) {
    string line;
    while (getline(nodeprops, line)) {
      stringstream ss(line);
      string id, prop, val;
      getline(ss, id, ',');
      getline(ss, prop, ',');
      getline(ss, val);
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

  // Sort contains vectors so the BBs and instructions are in order.
  for (auto& [_, ids] : db.contains) {
    sort(ids.begin(), ids.end());
  }

  return db;
}

database facts::load(const fs::path& facts_dir, LoadOptions options) {
  const string nodes_path = facts_dir / "nodes.facts";
  ifstream nodes(nodes_path);
  if (is_set(options, LoadOptions::NodeType) && !nodes.is_open()) {
    throw runtime_error("Failed to open: " + nodes_path);
  }

  const string edges_path = facts_dir / "edges.facts";
  ifstream edges(edges_path);
  if (is_set(options, LoadOptions::Edges) && !edges.is_open()) {
    throw runtime_error("Failed to open: " + edges_path);
  }

  const string nodeprops_path = facts_dir / "nodeprops.facts";
  ifstream nodeprops(nodeprops_path);
  if (is_set(options, LoadOptions::NodeProps) && !nodeprops.is_open()) {
    throw runtime_error("Failed to open: " + nodeprops_path);
  }

  return load(nodes, nodeprops, edges, options);
}

// These checks ensure at least that the hashmap lookups in
// graph::build_cfg will succeed.
bool facts::validate(const database& db) {
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

  // Nodes with Direct call type appear in [calls] and [fun_sig].
  unordered_map<ID, CallType> direct_calls(db.call_type);
  erase_if(direct_calls, [](const auto& item) {
    return item.second != CallType::Direct;
  });
  if (!(KEYS_SUBSET(direct_calls, db.calls) &&
        KEYS_SUBSET(direct_calls, db.fun_sig))) {
    return false;
  }

  // Nodes in [address_taken] appear in [fun_sig].
  for (const auto &id : db.address_taken) {
    if (!db.fun_sig.contains(id)) {
      std::cerr << "id " << id << " in db.address_taken"
                << " not found in db.fun_sig" << std::endl;
      return false;
    }
  }

  // Nodes in [linkage] appear in [fun_sig] and [name].
  if (!(KEYS_SUBSET(db.linkage, db.fun_sig) &&
        KEYS_SUBSET(db.linkage, db.name))) {
    return false;
  }

  return true;
}
