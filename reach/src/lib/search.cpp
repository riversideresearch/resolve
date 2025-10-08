#include <queue>

#include "binary_heap.hpp"
#include "graph.hpp"
#include "search.hpp"
#include "util.hpp"

using namespace std;

using K = search::K;

// Returns path from src to tgt.
optional<vector<graph::edge>>
search::path_bfs(const graph::E& g, const K& src, const K& tgt) {
  const graph::edge src_edge = { src, 1.0, graph::EdgeType::Self };
  
  // Queue of unvisited vertices.
  queue<graph::edge> frontier;
  frontier.push(src_edge);

  // Map each node to its predecessor on the path to src from tgt
  unordered_map<K, graph::edge> pred;
  pred.emplace(src, src_edge);

  while (!frontier.empty()) {
    const graph::edge& u = frontier.front();
    frontier.pop();

    if (u.node == tgt) {
      // Build path by stepping backward from tgt through the
      // predecessor map
      vector<graph::edge> path{u};
      auto cur = tgt;
      auto pre = pred.at(cur);
      while (cur != pre.node) {
	path.push_back(pre);
	cur = pre.node;
	pre = pred.at(cur);
      }
      reverse(path.begin(), path.end());
      return path;
    }

    for (const auto& e : g.at(u.node)) {
      if (!pred.contains(e.node)) {
	pred.emplace(e.node, u);
	frontier.push(e);
      }
    }
  }

  return std::nullopt;
}

// Returns true iff a path exists in [g] from [src] to [tgt]
bool search::reach_bfs(const graph::E& g, const K& src, const K& tgt) {
  return path_bfs(g, src, tgt).has_value();
}

optional<vector<graph::edge>>
dijkstra(const graph::E& g, const K src, const K tgt, const vector<size_t>& skip) {
  // Mapping of each vertex to its current tentative distance value.
  vector<double> dist(g.size(), std::numeric_limits<double>::max());

  // Initialize source vertex distance to 0.
  dist[src] = 0.0;

  // Mapping of each vertex to its immediate predecessor on the
  // current best-known path from the source.
  std::unordered_map<K, graph::edge> pred;
  const auto src_edge = graph::edge { src, 1.0, graph::EdgeType::Self };
  pred.emplace(src, src_edge);

  // Set of unvisited vertices.
  binary_heap<graph::edge, double> unvisited;
  unvisited.insert(src_edge, dist[src]);

  // Main loop
  while (unvisited.size()) {
    // Remove the vertex with the smallest tentative distance value
    // from the 'unvisited' set.
    const graph::edge& u = unvisited.extract().first;

    // If u.node is the target, we're done.
    if (u.node == tgt) {
      vector<graph::edge> path{u};
      auto cur = tgt;
      auto pre = pred.at(cur);
      while (cur != pre.node) {
	path.push_back(pre);
	cur = pre.node;
	pre = pred.at(cur);
      }
      reverse(path.begin(), path.end());
      return path;
    }

    // For each neighbor of 'u', update their tentative distance
    // values if it becomes shorter through 'u'.
    for (const auto& e : g.at(u.node)) {
      if (std::find(skip.begin(), skip.end(), u.node) != skip.end()) {
	continue;
      }
      const double d = dist[u.node] + e.weight;
      if (d < dist[e.node]) {
	dist[e.node] = d;
	pred[e.node] = u;
	if (!unvisited.contains(e)) {
	  unvisited.insert(e, d);
	} else {
	  unvisited.decrease_key(e, d);
	}
      }
    }
  }

  // If we've processed all vertices and never encountered the target,
  // it must not have existed in the graph.
  return std::nullopt;
}

optional<vector<graph::edge>>
search::path_dijkstra(const graph::E& g, const K& src, const K& tgt) {
  return dijkstra(g, src, tgt, {});
}

// void print_edges(const vector<graph::edge>& es) {
//   for (const auto& e : es) {
//     cout << e.node << "," << graph::EdgeType_to_string(e.type) << " ";
//   }
//   cout << endl;
// }

optional<graph::edge> find_and_remove(vector<graph::edge>& edges,
				      size_t node) {
  for (size_t i = 0; i < edges.size(); i++) {
    if (edges[i].node == node) {
      const auto e = edges[i];
      edges.erase(edges.begin() + i);
      return { e };
    }
  }
  return nullopt;
}

template <typename T>
bool prefix_eq(const vector<T>& a, const vector<T>& b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

vector<graph::edge> remove_used_edges(const vector<vector<graph::edge>>& paths,
				      vector<graph::edge>& edges,
				      size_t i) {
  vector<graph::edge> removed_edges;

  const auto& last_p = paths.back();
  for (const auto& p : paths) {
    if (prefix_eq(p, last_p, i)) {
      const auto e_opt = find_and_remove(edges, p[i].node);
      if (e_opt.has_value()) {
	removed_edges.push_back(e_opt.value());
      }
    }
  }

  return removed_edges;
}

vector<vector<graph::edge>>
search::k_paths_yen(const graph::E& g, const K& src, const K& tgt, size_t K) {
  vector<vector<graph::edge>> paths;

  const auto shortest_path_opt = path_dijkstra(g, src, tgt);
  if (!shortest_path_opt.has_value()) {
    return paths;
  }
  paths.push_back(shortest_path_opt.value());

  if (K <= 1) {
    return paths;
  }

  graph::E local_g(g);

  for (size_t k = 1; k < K; k++) {
    double min_weight = numeric_limits<double>::max();
    vector<graph::edge> min_path;
    const auto last_path = paths[k-1];

    for (size_t i = 0; i < last_path.size()-1; i++) {
      auto& edges = local_g.at(last_path[i].node);
      const auto es = remove_used_edges(paths, edges, i+1);

      vector<size_t> root;
      for (size_t j = 0; j < i; j++) {
        root.push_back(last_path[j].node);
      }

      const auto spur_opt = dijkstra(local_g, last_path[i].node, tgt, root);
      edges.insert(edges.end(), es.begin(), es.end());
      if (!spur_opt.has_value()) {
	continue;
      }
      auto spur = spur_opt.value();
      spur[0] = last_path[i];

      double weight = 0.0;
      vector<graph::edge> full_path;
      full_path.reserve(i + spur.size());
      for (size_t j = 0; j < i; j++) {
	full_path.push_back(last_path[j]);
	weight += last_path[j].weight;
      }
      for (const auto& x : spur) {
	full_path.push_back(x);
	weight += x.weight;
      }

      if (weight < min_weight) {
	min_weight = weight;
	min_path = full_path;
      }
    }

    if (min_weight == numeric_limits<double>::max()) {
      break;
    }

    paths.push_back(min_path);
  }

  return paths;
}

vector<vector<graph::edge>>
search::all_paths(const graph::E& g, const K& src, const K& tgt) {
  return {}; // TODO
}

vector<vector<graph::edge>>
search::k_shortest_paths(const graph::E& g,
			 const K& src,
			 const K& tgt,
			 size_t K) {
  return {}; // TODO
}

// Compute minimum distance from [src] for all nodes in [g] that are
// reachable from [src].
unordered_map<K, size_t> search::min_distances(const graph::E& g, const K& src) {
  // Queue of unvisited vertices.
  queue<K> frontier;
  frontier.push(src);

  unordered_map<K, size_t> dist;
  dist.emplace(src, 0);

  while (!frontier.empty()) {
    const K& u = frontier.front();
    frontier.pop();

    const auto d = dist.at(u);

    for (const auto& e : g.at(u)) {
      if (!dist.contains(e.node)) {
	dist.emplace(e.node, d + 1.0);
	frontier.push(e.node);
      }
    }
  }

  return dist;
}
