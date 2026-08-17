/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iterator>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "facts_rs.hpp"
#include "resolve_facts/resolve_facts.hpp"

namespace reach_facts {

static_assert(std::endian::native == std::endian::little);
static_assert(sizeof(facts_rs::ModuleHeader) == 16);
static_assert(alignof(facts_rs::ModuleHeader) == 4);
static_assert(sizeof(facts_rs::Node) == 32);
static_assert(alignof(facts_rs::Node) == 4);
static_assert(sizeof(facts_rs::Edge) == 12);
static_assert(alignof(facts_rs::Edge) == 4);

struct SourceLocation {
  uint32_t line;
  uint32_t column;
  bool operator==(const SourceLocation &) const = default;
};

class StringPoolView {
  std::span<const uint8_t> bytes_;

public:
  explicit StringPoolView(const std::span<const uint8_t> bytes)
      : bytes_(bytes) {}

  std::optional<std::string_view> get(const facts_rs::Interned id) const {
    const auto offset = static_cast<size_t>(id);
    if (offset > bytes_.size() || bytes_.size() - offset < sizeof(uint32_t)) {
      return {};
    }

    uint32_t length;
    std::memcpy(&length, bytes_.data() + offset, sizeof(length));
    const auto start = offset + sizeof(length);
    if (length > bytes_.size() - start) {
      return {};
    }

    return std::string_view{
        reinterpret_cast<const char *>(bytes_.data() + start), length};
  }

  std::span<const uint8_t> raw() const { return bytes_; }
};

class NodeView {
  const facts_rs::Node *node_;
  StringPoolView strings_;

  std::optional<std::string_view> string(const uint32_t property,
                                         const facts_rs::Interned id) const {
    if ((node_->meta & property) == 0) {
      return {};
    }
    return strings_.get(id);
  }

public:
  NodeView(const facts_rs::Node &node, const StringPoolView strings)
      : node_(&node), strings_(strings) {}

  const facts_rs::Node &raw() const { return *node_; }

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

  std::optional<uint32_t> idx() const {
    if ((node_->meta & facts_rs::P_IDX) == 0) {
      return {};
    }
    return node_->idx;
  }

  std::optional<std::string_view> function_type() const {
    return string(facts_rs::P_FUNCTION_TYPE, node_->function_type);
  }

  bool address_taken() const {
    return (node_->meta & facts_rs::P_ADDRESS_TAKEN) != 0;
  }

  std::optional<std::string_view> opcode() const {
    return string(facts_rs::P_OPCODE, node_->opcode);
  }

  std::optional<std::string_view> source_file() const {
    return string(facts_rs::P_SOURCE_FILE, node_->source_file);
  }

  std::optional<SourceLocation> source_loc() const {
    if ((node_->meta & facts_rs::P_SOURCE_LOC) == 0) {
      return {};
    }
    return SourceLocation{node_->source_line, node_->source_col};
  }
};

class NodeTableView {
  std::span<const facts_rs::Node> nodes_;
  StringPoolView strings_;

public:
  class iterator {
    const NodeTableView *table_ = nullptr;
    facts_rs::NodeID index_ = 0;

  public:
    using difference_type = std::ptrdiff_t;
    using value_type = std::pair<facts_rs::NodeID, NodeView>;
    using iterator_category = std::input_iterator_tag;

    iterator() = default;
    iterator(const NodeTableView *table, const facts_rs::NodeID index)
        : table_(table), index_(index) {}

    value_type operator*() const { return {index_, table_->at(index_)}; }
    iterator &operator++() {
      ++index_;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(const iterator &) const = default;
  };

  NodeTableView(const std::span<const facts_rs::Node> nodes,
                const StringPoolView strings)
      : nodes_(nodes), strings_(strings) {}

  NodeView at(const facts_rs::NodeID id) const {
    if (id >= nodes_.size()) {
      throw std::out_of_range("node ID is outside its module");
    }
    return {nodes_[id], strings_};
  }

  const facts_rs::Node &raw(const facts_rs::NodeID id) const {
    if (id >= nodes_.size()) {
      throw std::out_of_range("node ID is outside its module");
    }
    return nodes_[id];
  }

  std::span<const facts_rs::Node> raw() const { return nodes_; }
  StringPoolView strings() const { return strings_; }
  bool contains(const facts_rs::NodeID id) const { return id < nodes_.size(); }
  size_t size() const { return nodes_.size(); }
  iterator begin() const { return {this, 0}; }
  iterator end() const {
    return {this, static_cast<facts_rs::NodeID>(nodes_.size())};
  }
};

class EdgeKindsView {
  uint32_t bits_;

public:
  class iterator {
    uint32_t bits_ = 0;
    uint8_t kind_ = 6;

    void seek() {
      while (kind_ < 6 && (bits_ & (1u << kind_)) == 0) {
        ++kind_;
      }
    }

  public:
    using difference_type = std::ptrdiff_t;
    using value_type = facts_rs::EdgeKind;
    using iterator_category = std::input_iterator_tag;

    iterator() = default;
    iterator(const uint32_t bits, const uint8_t kind)
        : bits_(bits), kind_(kind) {
      seek();
    }

    value_type operator*() const {
      return static_cast<facts_rs::EdgeKind>(kind_);
    }
    iterator &operator++() {
      ++kind_;
      seek();
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(const iterator &) const = default;
  };

  explicit EdgeKindsView(const uint32_t bits) : bits_(bits) {}

  bool contains(const facts_rs::EdgeKind kind) const {
    return (bits_ & (1u << static_cast<uint8_t>(kind))) != 0;
  }
  iterator begin() const { return {bits_, 0}; }
  iterator end() const { return {bits_, 6}; }
};

class EdgeView {
  const facts_rs::Edge *edge_;

public:
  explicit EdgeView(const facts_rs::Edge &edge) : edge_(&edge) {}

  const facts_rs::Edge &raw() const { return *edge_; }
  EdgeKindsView kinds() const { return EdgeKindsView{edge_->kinds}; }
};

class EdgeTableView {
  std::span<const facts_rs::Edge> edges_;

public:
  class iterator {
    const EdgeTableView *table_ = nullptr;
    size_t index_ = 0;

  public:
    using difference_type = std::ptrdiff_t;
    using value_type = std::pair<resolve_facts::EdgeId, EdgeView>;
    using iterator_category = std::input_iterator_tag;

    iterator() = default;
    iterator(const EdgeTableView *table, const size_t index)
        : table_(table), index_(index) {}

    value_type operator*() const {
      const auto &edge = table_->edges_[index_];
      return {{edge.src, edge.dst}, EdgeView{edge}};
    }
    iterator &operator++() {
      ++index_;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(const iterator &) const = default;
  };

  explicit EdgeTableView(const std::span<const facts_rs::Edge> edges)
      : edges_(edges) {}

  const facts_rs::Edge &raw(const size_t index) const {
    if (index >= edges_.size()) {
      throw std::out_of_range("edge index is outside its module");
    }
    return edges_[index];
  }

  std::span<const facts_rs::Edge> raw() const { return edges_; }
  size_t size() const { return edges_.size(); }
  iterator begin() const { return {this, 0}; }
  iterator end() const { return {this, edges_.size()}; }
};

class ModuleView {
public:
  uint32_t index;
  NodeTableView nodes;
  EdgeTableView edges;

  explicit ModuleView(const facts_rs::FactsModuleView &module)
      : index(module.module_index),
        nodes(std::span{module.nodes, module.node_count},
              StringPoolView{
                  std::span{module.string_pool, module.string_pool_len}}),
        edges(std::span{module.edges, module.edge_count}) {}

  StringPoolView strings() const { return nodes.strings(); }
};

class ModuleTableView {
  std::vector<ModuleView> modules_;

public:
  class iterator {
    const ModuleTableView *table_ = nullptr;
    uint32_t index_ = 0;

  public:
    using difference_type = std::ptrdiff_t;
    using value_type = std::pair<uint32_t, ModuleView>;
    using iterator_category = std::input_iterator_tag;

    iterator() = default;
    iterator(const ModuleTableView *table, const uint32_t index)
        : table_(table), index_(index) {}

    value_type operator*() const { return {index_, table_->at(index_)}; }
    iterator &operator++() {
      ++index_;
      return *this;
    }
    void operator++(int) { ++*this; }
    bool operator==(const iterator &) const = default;
  };

  explicit ModuleTableView(std::vector<ModuleView> modules)
      : modules_(std::move(modules)) {}

  const ModuleView &at(const uint32_t index) const {
    return modules_.at(index);
  }
  size_t size() const { return modules_.size(); }
  iterator begin() const { return {this, 0}; }
  iterator end() const {
    return {this, static_cast<uint32_t>(modules_.size())};
  }
};

class ProgramFactsView {
  static std::vector<ModuleView> read_modules(const facts_rs::FactsBuf *facts) {
    if (!facts) {
      throw std::invalid_argument("null FactsBuf");
    }

    std::vector<ModuleView> modules;
    facts_rs::FactsModuleCursor cursor{};
    facts_rs::FactsModuleView module{};
    while (facts_rs::facts_module_next(facts, &cursor, &module)) {
      modules.emplace_back(module);
    }
    return modules;
  }

public:
  ModuleTableView modules;

  explicit ProgramFactsView(const facts_rs::FactsBuf *facts)
      : modules(read_modules(facts)) {}

  bool containsNode(const resolve_facts::NamespacedNodeId id) const {
    const auto [module, node] = id;
    return module < modules.size() && modules.at(module).nodes.contains(node);
  }

  NodeView getNode(const resolve_facts::NamespacedNodeId id) const {
    const auto [module, node] = id;
    return modules.at(module).nodes.at(node);
  }

  NodeView getModuleOfNode(const resolve_facts::NamespacedNodeId id) const {
    return modules.at(id.first).nodes.at(0);
  }
};

class FactsOwner {
  facts_rs::FactsBuf *facts_ = nullptr;

public:
  explicit FactsOwner(facts_rs::FactsBuf *facts) : facts_(facts) {
    if (!facts_) {
      throw std::invalid_argument("null FactsBuf");
    }
  }

  ~FactsOwner() { facts_rs::facts_buf_free(facts_); }

  FactsOwner(const FactsOwner &) = delete;
  FactsOwner &operator=(const FactsOwner &) = delete;

  FactsOwner(FactsOwner &&other) noexcept
      : facts_(std::exchange(other.facts_, nullptr)) {}

  FactsOwner &operator=(FactsOwner &&other) noexcept {
    if (this != &other) {
      facts_rs::facts_buf_free(facts_);
      facts_ = std::exchange(other.facts_, nullptr);
    }
    return *this;
  }

  static FactsOwner read(const std::vector<std::filesystem::path> &paths) {
    std::vector<std::string> strings;
    strings.reserve(paths.size());
    for (const auto &path : paths) {
      strings.push_back(path.string());
    }

    std::vector<facts_rs::FactsPath> inputs;
    inputs.reserve(strings.size());
    for (const auto &path : strings) {
      inputs.push_back(
          {reinterpret_cast<const uint8_t *>(path.data()), path.size()});
    }

    auto result = facts_rs::facts_read_files(inputs.data(), inputs.size());
    if (result.error) {
      const auto message =
          std::string{reinterpret_cast<const char *>(
                          facts_rs::facts_read_error_data(result.error)),
                      facts_rs::facts_read_error_len(result.error)};
      facts_rs::facts_read_error_free(result.error);
      throw std::runtime_error(message);
    }
    return FactsOwner{result.facts};
  }

  const facts_rs::FactsBuf *get() const { return facts_; }
  ProgramFactsView view() const { return ProgramFactsView{facts_}; }
};

} // namespace reach_facts
