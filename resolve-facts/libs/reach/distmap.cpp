/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "reach/distmap.hpp"
#include "reach/facts_view.hpp"
#include "reach/search.hpp"
#include "reach/util.hpp"

using namespace std;

namespace {

template <typename Function>
void for_each_function_instruction(const reach_facts::ProgramFactsView &pf,
                                   const NNodeId function, Function callback) {
  const auto [module_id, function_id] = function;
  const auto module = pf.module(module_id);
  for (const auto &contains_block : module.out_edges(function_id)) {
    if (!reach_facts::edge_has_kind(contains_block,
                                    facts_rs::EdgeKind::Contains) ||
        module.node(contains_block.dst).type() !=
            facts_rs::NodeType::BasicBlock) {
      continue;
    }
    for (const auto &contains_instruction :
         module.out_edges(contains_block.dst)) {
      if (reach_facts::edge_has_kind(contains_instruction,
                                     facts_rs::EdgeKind::Contains) &&
          module.node(contains_instruction.dst).type() ==
              facts_rs::NodeType::Instruction) {
        callback(make_pair(module_id, contains_instruction.dst));
      }
    }
  }
}

} // namespace

distmap_blacklist
distmap::gen(const facts_rs::FactsBuf *facts, const NNodeId &dst, bool dynlink,
             const optional<vector<dlsym::loaded_symbol>> &loaded_syms) {
  const reach_facts::ProgramFactsView pf{facts};
  if (!pf.contains_node(dst)) {
    throw runtime_error("distmap::gen: node not found");
  }
  const auto target = pf.node(dst);
  if (target.type() != facts_rs::NodeType::Function) {
    throw runtime_error("distmap::gen: node is not a function");
  }
  const auto target_name = target.name();
  if (!target_name) {
    throw runtime_error("distmap::gen: target function has no name");
  }

  const auto graph = graph::build_instr_cfg(facts, dynlink, loaded_syms);
  auto distances = search::min_distances(graph.edges, dst);

  for_each_function_instruction(
      pf, dst, [&](const NNodeId instruction) { distances[instruction] = 0; });

  for (uint32_t module_id = 0; module_id < pf.module_count(); ++module_id) {
    const auto module = pf.module(module_id);
    for (uint32_t node_id = 0; node_id < module.nodes().size(); ++node_id) {
      const auto node = module.node(node_id);
      if (node.linkage() == facts_rs::Linkage::ExternalLinkage &&
          node.name() == target_name) {
        for_each_function_instruction(
            pf, make_pair(module_id, node_id),
            [&](const NNodeId instruction) { distances[instruction] = 0; });
      }
    }
  }

  resolve_facts::NodeMap<size_t> instruction_distances;
  for (const auto &[id, distance] : distances) {
    if (pf.node(id).type() == facts_rs::NodeType::Instruction) {
      instruction_distances.emplace(id, distance);
    }
  }

  unordered_set<NNodeId, resolve_facts::pair_hash> blacklist;
  for (uint32_t module_id = 0; module_id < pf.module_count(); ++module_id) {
    const auto module = pf.module(module_id);
    for (uint32_t node_id = 0; node_id < module.nodes().size(); ++node_id) {
      const auto id = make_pair(module_id, node_id);
      if (module.node(node_id).type() == facts_rs::NodeType::Instruction &&
          !instruction_distances.contains(id)) {
        blacklist.insert(id);
      }
    }
  }

  return {move(instruction_distances), move(blacklist)};
}

distmap_blacklist
distmap::gen(const reach_facts::database &db, const NNodeId &dst, bool dynlink,
             const optional<vector<dlsym::loaded_symbol>> &loaded_syms) {
  const auto g = graph::build_instr_cfg(db, dynlink, loaded_syms);

  if (!db.node_type.contains(dst)) {
    throw runtime_error("distmap::gen: node not found");
  }
  if (db.node_type.at(dst) != resolve_facts::NodeType::Function) {
    throw runtime_error("distmap::gen: node is not a function");
  }

  auto distmap = search::min_distances(g.edges, dst);

  // Add zero-distance entries for all BBs contained within the
  // destination.
  if (db.contains.contains(dst)) {
    for (const auto &bb : db.contains.at(dst)) {
      if (db.node_type.at(bb) != resolve_facts::NodeType::BasicBlock) {
        continue;
      }
      for (const auto &instr : db.contains.at(bb)) {
        distmap[instr] = 0;
      }
    }
  }

  // Do the same for all nodes with external linkage with the same name.
  const auto dst_name = db.name.at(dst);
  for (const auto &[id, linkage] : db.linkage) {
    if (linkage != resolve_facts::Linkage::ExternalLinkage) {
      continue;
    }
    const auto id_name = db.name.at(id);
    if (id_name != dst_name) {
      continue;
    }
    if (db.contains.contains(id)) {
      for (const auto &bb : db.contains.at(id)) {
        if (db.node_type.at(bb) != resolve_facts::NodeType::BasicBlock) {
          continue;
        }
        for (const auto &instr : db.contains.at(bb)) {
          distmap[instr] = 0;
        }
      }
    }
  }

  // Build distmap with node id keys
  resolve_facts::NodeMap<size_t> id_distmap;
  for (const auto &[id, d] : distmap) {
    if (db.node_type.at(id) == resolve_facts::NodeType::Instruction) {
      id_distmap.emplace(id, d);
    }
  }

  // Build blacklist of node ids
  unordered_set<NNodeId, resolve_facts::pair_hash> blacklist;
  for (const auto &[id, ty] : db.node_type) {
    if (ty == resolve_facts::NodeType::Instruction &&
        !id_distmap.contains(id)) {
      blacklist.insert(id);
    }
  }

  return {id_distmap, blacklist};
}
