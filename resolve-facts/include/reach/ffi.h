/*
 *   Copyright (c) 2026 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include "facts_rs.hpp"
using ReachFactsBuf = facts_rs::FactsBuf;
extern "C" {
#else
typedef struct ReachFactsBuf ReachFactsBuf;
#endif

typedef struct ReachGraph ReachGraph;
typedef struct ReachQueryResult ReachQueryResult;
typedef struct ReachError ReachError;

typedef struct ReachStringView {
  const uint8_t *data;
  size_t len;
} ReachStringView;

typedef struct ReachLoadedSymbol {
  ReachStringView symbol;
  ReachStringView library;
} ReachLoadedSymbol;

typedef struct ReachBuildOptions {
  const ReachLoadedSymbol *loaded_symbols;
  size_t loaded_symbol_count;
  uint8_t dynlink;
  uint8_t filter_loaded_symbols;
} ReachBuildOptions;

typedef struct ReachNodeId {
  uint32_t module;
  uint32_t node;
} ReachNodeId;

typedef uint8_t ReachEdgeType;
enum {
  REACH_EDGE_DIRECT_CALL = 0,
  REACH_EDGE_INDIRECT_CALL = 1,
  REACH_EDGE_CONTAINS = 2,
  REACH_EDGE_SUCCESSOR = 3,
  REACH_EDGE_EXTERNAL = 4,
  REACH_EDGE_EXTERNAL_INDIRECT_CALL = 5,
};

typedef struct ReachPathView {
  const ReachNodeId *nodes;
  size_t node_count;
  const ReachEdgeType *edges;
  size_t edge_count;
} ReachPathView;

// Borrows facts and all option slices only for this call. The returned graph
// owns only the derived reachability graph and must be freed by the caller.
ReachGraph *reach_graph_build(const ReachFactsBuf *facts,
                              const ReachBuildOptions *options,
                              ReachError **error);
void reach_graph_free(ReachGraph *graph);
size_t reach_graph_edge_count(const ReachGraph *graph);

ReachQueryResult *reach_graph_query(const ReachGraph *graph, ReachNodeId src,
                                    ReachNodeId dst, size_t max_paths,
                                    ReachError **error);
void reach_query_result_free(ReachQueryResult *result);
size_t reach_query_result_path_count(const ReachQueryResult *result);
// The returned slices borrow result and remain valid until it is freed.
uint8_t reach_query_result_path(const ReachQueryResult *result, size_t index,
                                ReachPathView *path);

const uint8_t *reach_error_data(const ReachError *error);
size_t reach_error_len(const ReachError *error);
void reach_error_free(ReachError *error);

#ifdef __cplusplus
} // extern "C"
#endif
