/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
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
    bool dynlink = false;
    std::optional<std::filesystem::path> out_path = {};
    std::optional<std::filesystem::path> dlsym_log_path = {};
    std::string graph_type = "";
    std::optional<size_t> num_paths = {};
    bool validate_facts = false;
    bool verbose = false;
  };

  // Generate JSON deserializers for config
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(query, src, dst);
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT
  (config, facts_dir, queries, dynlink, out_path,
   dlsym_log_path, graph_type, num_paths, validate_facts, verbose);

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
    double facts_load_time;
    double graph_build_time;
    std::vector<query_result> query_results;
  };

  // Generate JSON serializers for results
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (path, nodes, edges)
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (query_result, query_time, src, dst, paths);
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
  (results, facts_load_time, graph_build_time, query_results);
}  // namespace output
