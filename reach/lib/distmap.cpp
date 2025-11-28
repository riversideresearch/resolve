/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "distmap.hpp"
#include "search.hpp"
#include "util.hpp"

using namespace std;

distmap_blacklist
distmap::gen(const reach_facts::database& db,
             const NNodeId& dst,
             bool dynlink,
             const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
  const auto g = graph::build_instr_cfg(db, dynlink, loaded_syms);

  if (!g.edges.contains(dst)) {
    throw runtime_error("distmap::gen: node not found");
  }
  auto distmap = search::min_distances(g.edges, dst);

  // Add zero-distance entries for all BBs contained within the
  // destination.
  if (db.contains.contains(dst)) {
    for (const auto& bb : db.contains.at(dst)) {
      if (db.node_type.at(bb) != resolve_facts::NodeType::BasicBlock) {
        continue;
      }
      for (const auto& instr : db.contains.at(bb)) {
        distmap[instr] = 0;
      }
    }
  }

  // Do the same for all nodes with external linkage with the same name.
  const auto dst_name = db.name.at(dst);
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage != resolve_facts::Linkage::ExternalLinkage) {
      continue;
    }
    const auto id_name = db.name.at(id);
    if (id_name != dst_name) {
      continue;
    }
    if (db.contains.contains(id)) {
      for (const auto& bb : db.contains.at(id)) {
        if (db.node_type.at(bb) != resolve_facts::NodeType::BasicBlock) {
          continue;
        }
        for (const auto& instr : db.contains.at(bb)) {
          distmap[instr] = 0;
        }
      }
    }
  }

  // Build distmap with node id keys
  resolve_facts::NodeMap<size_t> id_distmap;
  for (const auto& [id, d] : distmap) {
    if (db.node_type.at(id) == resolve_facts::NodeType::Instruction) {
      id_distmap.emplace(id, d);
    }
  }

  // Build blacklist of node ids
  unordered_set<NNodeId, resolve_facts::pair_hash> blacklist;
  for (const auto& [id, ty] : db.node_type) {
    if (ty == resolve_facts::NodeType::Instruction && !id_distmap.contains(id)) {
      blacklist.insert(id);
    }
  }

  return { id_distmap, blacklist };
}
