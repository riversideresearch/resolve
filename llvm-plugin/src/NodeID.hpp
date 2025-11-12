/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#ifndef RESOLVE_LLVM_NODEID_HPP
#define RESOLVE_LLVM_NODEID_HPP

#include <string>

class NodeID {
  std::string id;

public:
  NodeID operator+(const std::string &segment) {
    if (segment.empty())
      return id;

    return id + (id.empty() ? "" : ":") + segment;
  }

  NodeID &operator+=(const std::string &segment) {
    if (segment.empty())
      return *this;

    id += (id.empty() ? "" : ":") + segment;
    return *this;
  }

  NodeID() : id() {}
  NodeID(std::string str) : id(str) {}
  NodeID(const char *str) : id(str) {}

  operator std::string() const { return id; };
};

#endif // RESOLVE_LLVM_NODEID_HPP