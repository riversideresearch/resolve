/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <bit>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "facts_rs.hpp"

namespace reach_facts {

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(facts_rs::Node) == 32);
static_assert(alignof(facts_rs::Node) == 4);
static_assert(sizeof(facts_rs::Edge) == 12);
static_assert(alignof(facts_rs::Edge) == 4);

class NodeView {
  const facts_rs::Node *node_;
  std::span<const uint8_t> strings_;

  std::string_view string_at(const facts_rs::Interned id) const {
    const auto offset = static_cast<size_t>(id);
    assert(offset + sizeof(uint32_t) <= strings_.size());

    uint32_t length;
    std::memcpy(&length, strings_.data() + offset, sizeof(length));
    const auto start = offset + sizeof(length);
    assert(start + length <= strings_.size());
    return {reinterpret_cast<const char *>(strings_.data() + start), length};
  }

  std::optional<std::string_view> string(const uint32_t property,
                                         const facts_rs::Interned id) const {
    if ((node_->meta & property) == 0) {
      return {};
    }
    return string_at(id);
  }

public:
  NodeView(const facts_rs::Node &node, const std::span<const uint8_t> strings)
      : node_(&node), strings_(strings) {}

  facts_rs::NodeType type() const {
    return static_cast<facts_rs::NodeType>(
        (node_->meta & facts_rs::NODE_TYPE_MASK) >> facts_rs::NODE_TYPE_SHIFT);
  }

  std::optional<std::string_view> name() const {
    return string(facts_rs::P_NAME, node_->name);
  }

  std::optional<facts_rs::Linkage> linkage() const {
    if ((node_->meta & facts_rs::P_LINKAGE) == 0) {
      return {};
    }
    return static_cast<facts_rs::Linkage>(
        (node_->meta & facts_rs::LINKAGE_MASK) >> facts_rs::LINKAGE_SHIFT);
  }

  std::optional<facts_rs::CallType> call_type() const {
    if ((node_->meta & facts_rs::P_CALL_TYPE) == 0) {
      return {};
    }
    return static_cast<facts_rs::CallType>(
        (node_->meta & facts_rs::CALL_TYPE_MASK) >> facts_rs::CALL_TYPE_SHIFT);
  }

  std::optional<std::string_view> source_file() const {
    return string(facts_rs::P_SOURCE_FILE, node_->source_file);
  }

  std::optional<std::string_view> function_type() const {
    return string(facts_rs::P_FUNCTION_TYPE, node_->function_type);
  }

  bool address_taken() const {
    return (node_->meta & facts_rs::P_ADDRESS_TAKEN) != 0;
  }
};

inline bool edge_has_kind(const facts_rs::Edge &edge,
                          const facts_rs::EdgeKind kind) {
  return (edge.kinds & (1u << static_cast<uint8_t>(kind))) != 0;
}

class ModuleView {
  facts_rs::FactsModuleView module_;

public:
  explicit ModuleView(const facts_rs::FactsModuleView module)
      : module_(module) {}

  std::span<const facts_rs::Node> nodes() const {
    return {module_.nodes, module_.node_count};
  }

  std::span<const facts_rs::Edge> edges() const {
    return {module_.edges, module_.edge_count};
  }

  bool contains(const facts_rs::NodeID id) const { return id < nodes().size(); }

  NodeView node(const facts_rs::NodeID id) const {
    assert(contains(id));
    return {nodes()[id], {module_.string_pool, module_.string_pool_len}};
  }
};

class ProgramFactsView {
  std::vector<facts_rs::FactsModuleView> modules_;

public:
  explicit ProgramFactsView(const facts_rs::FactsBuf *facts) {
    if (!facts) {
      throw std::invalid_argument("null FactsBuf");
    }
    facts_rs::FactsModuleCursor cursor{};
    facts_rs::FactsModuleView module{};
    while (facts_rs::facts_module_next(facts, &cursor, &module)) {
      modules_.push_back(module);
    }
  }

  size_t module_count() const { return modules_.size(); }

  ModuleView module(const uint32_t index) const {
    assert(index < modules_.size());
    return ModuleView{modules_[index]};
  }

  bool contains_node(const std::pair<uint32_t, uint32_t> id) const {
    return id.first < modules_.size() && module(id.first).contains(id.second);
  }

  NodeView node(const std::pair<uint32_t, uint32_t> id) const {
    return module(id.first).node(id.second);
  }
};

} // namespace reach_facts
