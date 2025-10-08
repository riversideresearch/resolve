#include "distmap.hpp"
#include "search.hpp"
#include "util.hpp"

using namespace std;

distmap_blacklist
distmap::gen(const facts::database& db,
	     const string& dst,
	     bool dynlink,
	     const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
  const auto [hm, g] = graph::build_instr_cfg(db, dynlink, loaded_syms);

  const auto dst_handle_opt = hm.getHandleOpt(dst);
  if (!dst_handle_opt.has_value()) {
    throw runtime_error("distmap::gen: node '" + dst + "' not found");
  }
  const auto dst_handle = dst_handle_opt.value();
  auto distmap = search::min_distances(g.edges, dst_handle);

  // Add zero-distance entries for all BBs contained within the
  // destination.
  if (db.contains.contains(dst)) {
    for (const auto& bb : db.contains.at(dst)) {
      if (db.node_type.at(bb) != facts::NodeType::BasicBlock) {
	continue;
      }
      for (const auto& instr : db.contains.at(bb)) {
	distmap[hm.getHandleConst(instr)] = 0;
      }
    }
  }

  // Do the same for all nodes with external linkage with the same name.
  const auto dst_name = util::name_of_id(dst);
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage != facts::Linkage::ExternalLinkage) {
      continue;
    }
    const auto id_name = util::name_of_id(id);
    if (id_name != dst_name) {
      continue;
    }
    if (db.contains.contains(id)) {
      for (const auto& bb : db.contains.at(id)) {
	if (db.node_type.at(bb) != facts::NodeType::BasicBlock) {
	  continue;
	}
	for (const auto& instr : db.contains.at(bb)) {
	  distmap[hm.getHandleConst(instr)] = 0;
	}
      }
    }
  }

  // Build distmap with node id keys
  unordered_map<string, size_t> id_distmap;
  for (const auto& [h, d] : distmap) {
    const auto id = hm.getId(h);
    if (AT(db.node_type, id) == facts::NodeType::Instruction) {
      id_distmap.emplace(id, d);
    }
  }

  // Build blacklist of node ids
  unordered_set<string> blacklist;
  for (const auto& [id, ty] : db.node_type) {
    if (ty == facts::NodeType::Instruction && !id_distmap.contains(id)) {
      blacklist.insert(id);
    }
  }

  return { id_distmap, blacklist };
}
