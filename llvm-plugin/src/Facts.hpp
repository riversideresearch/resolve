/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#ifndef RESOLVE_LLVM_FACTS_HPP
#define RESOLVE_LLVM_FACTS_HPP

#include <string>

struct Facts {
  std::string nodes;
  std::string nodeProps;
  std::string edges;
  std::string edgeProps;

  /// Record a node fact.
  void recordNode(const std::string &id, const std::string &type) {
    nodes += id + "," + type + "\n";
  }

  /// Record a node property.
  void recordNodeProp(const std::string &nodeID, const std::string &key,
                      const std::string &value) {
    nodeProps += nodeID + "," + key + "," + value + "\n";
  }

  /// Record an edge fact.
  void recordEdge(const std::string &edgeID, const std::string &type,
                  const std::string &srcID, const std::string &tgtID) {
    edges += edgeID + "," + type + "," + srcID + "," + tgtID + "\n";
  }

  /// Record an edge property.
  void recordEdgeProp(const std::string &edgeID, const std::string &key,
                      const std::string &value) {
    edgeProps += edgeID + "," + key + "," + value + "\n";
  }
};

#endif // RESOLVE_LLVM_FACTS_HPP