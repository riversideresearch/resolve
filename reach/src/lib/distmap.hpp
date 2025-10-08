#pragma once

#include "facts.hpp"

struct distmap_blacklist {
  std::unordered_map<std::string, size_t> distmap;
  std::unordered_set<std::string> blacklist;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
(distmap_blacklist, distmap, blacklist);

namespace distmap {
  distmap_blacklist
  gen(const facts::database& db,
      const std::string& dst,
      bool dynlink = false,
      const std::optional<std::vector<dlsym::loaded_symbol>>& loaded_syms = {});
}
