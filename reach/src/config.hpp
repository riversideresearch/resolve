/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "json.hpp"

namespace conf {
  struct query {
    std::string src;
    std::string dst;
  };

  struct config {
    std::filesystem::path facts_dir;
    std::vector<query> queries;
    bool dynlink;
    bool distmap;
    std::optional<std::filesystem::path> out_path;
    std::optional<std::filesystem::path> dlsym_log_path;
    std::string graph_type;
    size_t num_paths;
  };

  // Generate JSON deserializers for config
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(query, src, dst);
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT
  (config, facts_dir, queries, dynlink, distmap, dlsym_log_path,
   out_path, graph_type, num_paths);

  // Load config from JSON file
  inline std::optional<config>
  load_config_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
      return {};
    }
    nlohmann::json j;
    f >> j;
    return j.template get<config>();
  }
}  // namespace conf

namespace output {
  struct path {
    std::vector<std::string> nodes;
    std::vector<std::string> edges;
  };

  struct query_result {
    double query_time;
    std::string src;
    std::string dst;
    std::vector<path> paths;
  };

  struct results {
    double load_time;
    std::vector<query_result> query_results;
  };

  // Generate JSON serializers for results
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (path, nodes, edges)
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (query_result, query_time, src, dst, paths);
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (results, load_time, query_results);
}  // namespace output
