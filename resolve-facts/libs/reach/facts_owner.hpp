/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "facts_rs.hpp"

namespace reach_facts {

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
};

} // namespace reach_facts
