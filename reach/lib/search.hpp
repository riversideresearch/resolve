#pragma once

#include "graph.hpp"

namespace search {
  using K = size_t;

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
  std::unordered_map<size_t, size_t> min_distances(const graph::E& g, const K& src);
} // search
