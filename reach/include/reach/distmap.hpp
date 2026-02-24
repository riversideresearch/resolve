/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "reach/facts.hpp"

using NNodeId = resolve_facts::NamespacedNodeId;

struct distmap_blacklist {
  resolve_facts::NodeMap<size_t> distmap;
  std::unordered_set<NNodeId, resolve_facts::pair_hash> blacklist;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
(distmap_blacklist, distmap, blacklist);

namespace distmap {
  distmap_blacklist
  gen(const reach_facts::database& db,
      const NNodeId& dst,
      bool dynlink = false,
      const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
}
