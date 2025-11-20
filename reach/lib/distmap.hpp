/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "facts.hpp"

using NNodeId = ReachFacts::NamespacedNodeId;

struct distmap_blacklist {
  ReachFacts::NodeMap<size_t> distmap;
  std::unordered_set<NNodeId, ReachFacts::pair_hash> blacklist;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
(distmap_blacklist, distmap, blacklist);

namespace distmap {
  distmap_blacklist
  gen(const ReachFacts::database& db,
      const NNodeId& dst,
      bool dynlink = false,
      const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
}
