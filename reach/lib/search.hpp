/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <unordered_map>
#include <vector>

#include "graph.hpp"

namespace search {
  using K = NNodeId;

  // Returns path from src to tgt in reverse order
  std::optional<std::vector<graph::edge>>
  path_bfs(const graph::E& g, const K& src, const K& tgt);

  bool reach_bfs(const graph::E& g, const K& src, const K& tgt);

  std::optional<std::vector<graph::edge>>
  path_dijkstra(const graph::E& g, const K& src, const K& tgt);

  std::vector<std::vector<graph::edge>>
  k_paths_yen(const graph::E& g, const K& src, const K& tgt, size_t k);

  std::vector<std::vector<graph::edge>>
  all_paths(const graph::E& g, const K& src, const K& tgt);

  std::vector<std::vector<graph::edge>>
  k_shortest_paths(const graph::E& g, const K& src, const K& tgt, size_t K);

  // Build distances map wrt. given graph and source node
  resolve_facts::NodeMap<size_t> min_distances(const graph::E& g, const K& src);
}  // namespace search
