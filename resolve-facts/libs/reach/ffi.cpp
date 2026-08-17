/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "reach/ffi.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "reach/facts_view.hpp"
#include "reach/graph.hpp"
#include "reach/search.hpp"

struct ReachGraph {
  graph::T value;
};

struct ReachPath {
  std::vector<ReachNodeId> nodes;
  std::vector<ReachEdgeType> edges;
};

struct ReachQueryResult {
  std::vector<ReachPath> paths;
};

struct ReachError {
  std::string message;
};

namespace {

void clear_error(ReachError **error) {
  if (error) {
    *error = nullptr;
  }
}

void set_error(ReachError **error, std::string message) {
  if (error) {
    *error = new ReachError{std::move(message)};
  }
}

std::string copy_string(const ReachStringView string) {
  if (string.len == 0) {
    return {};
  }
  if (!string.data) {
    throw std::invalid_argument("null loaded-symbol string");
  }
  return {reinterpret_cast<const char *>(string.data), string.len};
}

std::optional<std::vector<dlsym::loaded_symbol>>
loaded_symbols(const ReachBuildOptions *options) {
  if (!options || options->filter_loaded_symbols == 0) {
    return {};
  }
  if (options->loaded_symbol_count != 0 && !options->loaded_symbols) {
    throw std::invalid_argument("null loaded-symbol array");
  }

  std::vector<dlsym::loaded_symbol> symbols;
  symbols.reserve(options->loaded_symbol_count);
  for (size_t i = 0; i < options->loaded_symbol_count; ++i) {
    const auto &symbol = options->loaded_symbols[i];
    symbols.push_back(
        {copy_string(symbol.symbol), copy_string(symbol.library)});
  }
  return symbols;
}

NNodeId node_id(const ReachNodeId id) { return {id.module, id.node}; }

ReachNodeId node_id(const NNodeId id) { return {id.first, id.second}; }

ReachEdgeType edge_type(const graph::EdgeType type) {
  switch (type) {
  case graph::EdgeType::DirectCall:
    return REACH_EDGE_DIRECT_CALL;
  case graph::EdgeType::IndirectCall:
    return REACH_EDGE_INDIRECT_CALL;
  case graph::EdgeType::Contains:
    return REACH_EDGE_CONTAINS;
  case graph::EdgeType::Succ:
    return REACH_EDGE_SUCCESSOR;
  case graph::EdgeType::Extern:
    return REACH_EDGE_EXTERNAL;
  case graph::EdgeType::ExternIndirectCall:
    return REACH_EDGE_EXTERNAL_INDIRECT_CALL;
  case graph::EdgeType::Self:
    throw std::logic_error("self edge cannot appear between path nodes");
  }
  throw std::logic_error("unknown reach edge type");
}

ReachPath convert_path(const std::vector<graph::edge> &path) {
  ReachPath result;
  result.nodes.reserve(path.size());
  result.edges.reserve(path.empty() ? 0 : path.size() - 1);

  for (const auto &edge : path) {
    result.nodes.push_back(node_id(edge.node));
  }
  std::reverse(result.nodes.begin(), result.nodes.end());

  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    if (std::next(it) != path.rend()) {
      result.edges.push_back(edge_type(it->type));
    }
  }
  return result;
}

} // namespace

extern "C" ReachGraph *reach_graph_build(const ReachFactsBuf *facts,
                                         const ReachBuildOptions *options,
                                         ReachError **error) {
  clear_error(error);
  try {
    const auto view = reach_facts::ProgramFactsView{facts};
    const auto symbols = loaded_symbols(options);
    const auto dynlink = options && options->dynlink != 0;
    return new ReachGraph{
        graph::build_from_program_facts(view, dynlink, symbols)};
  } catch (const std::exception &exception) {
    set_error(error, exception.what());
  } catch (...) {
    set_error(error, "unknown error while building reach graph");
  }
  return nullptr;
}

extern "C" void reach_graph_free(ReachGraph *graph) { delete graph; }

extern "C" size_t reach_graph_edge_count(const ReachGraph *graph) {
  if (!graph) {
    return 0;
  }

  size_t count = 0;
  for (const auto &[_, edges] : graph->value.edges) {
    count += edges.size();
  }
  return count;
}

extern "C" ReachQueryResult *reach_graph_query(const ReachGraph *graph,
                                               const ReachNodeId src,
                                               const ReachNodeId dst,
                                               const size_t max_paths,
                                               ReachError **error) {
  clear_error(error);
  try {
    if (!graph) {
      throw std::invalid_argument("null reach graph");
    }

    const auto paths = search::k_paths_yen(graph->value.edges, node_id(dst),
                                           node_id(src), max_paths);
    auto result = std::make_unique<ReachQueryResult>();
    result->paths.reserve(paths.size());
    for (const auto &path : paths) {
      result->paths.push_back(convert_path(path));
    }
    return result.release();
  } catch (const std::exception &exception) {
    set_error(error, exception.what());
  } catch (...) {
    set_error(error, "unknown error while querying reach graph");
  }
  return nullptr;
}

extern "C" void reach_query_result_free(ReachQueryResult *result) {
  delete result;
}

extern "C" size_t
reach_query_result_path_count(const ReachQueryResult *result) {
  return result ? result->paths.size() : 0;
}

extern "C" uint8_t reach_query_result_path(const ReachQueryResult *result,
                                           const size_t index,
                                           ReachPathView *path) {
  if (!result || !path || index >= result->paths.size()) {
    return 0;
  }

  const auto &value = result->paths[index];
  *path = {
      value.nodes.data(),
      value.nodes.size(),
      value.edges.data(),
      value.edges.size(),
  };
  return 1;
}

extern "C" const uint8_t *reach_error_data(const ReachError *error) {
  return error ? reinterpret_cast<const uint8_t *>(error->message.data())
               : nullptr;
}

extern "C" size_t reach_error_len(const ReachError *error) {
  return error ? error->message.size() : 0;
}

extern "C" void reach_error_free(ReachError *error) { delete error; }
