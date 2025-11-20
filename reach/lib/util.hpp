/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include <chrono>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#define AT(map, key) util::at(map, key, #map)
#define KEYS_SUBSET(a, b) util::keys_subset(#a, a, #b, b)

#define DB_ERR(id, m1, m2) \
  std::cerr << "id " << id << " in " << #m1 << " not found in " << #m2 << std::endl

namespace util {
  template <typename K, typename V, typename H>
  inline V at(const std::unordered_map<K, V, H>& m, const K& k, const std::string& msg) {
    try {
      return m.at(k);
    }
    catch (...) {
      std::stringstream ss;
      // TODO: I think this is getting deleted anyways
      //ss << msg << ": key " << k << " not found";
      throw std::runtime_error(ss.str());
    }
  }

  template <typename T>
  inline T at(const std::vector<T>& v, size_t i, const std::string& msg) {
    try {
      return v.at(i);
    }
    catch (...) {
      std::stringstream ss;
      ss << msg << ": index " << i << " out of bounds";
      throw std::runtime_error(ss.str());
    }
  }

  template <typename T>
  std::pair<std::chrono::duration<double>, T> time(const std::function<T()>& f) {
    const std::chrono::time_point<std::chrono::system_clock> t0 =
      std::chrono::system_clock::now();
    const T res = f();
    const std::chrono::time_point<std::chrono::system_clock> t1 =
      std::chrono::system_clock::now();
    return { t1 - t0, res };
  }

  // Split string by single character delimiter.
  std::vector<std::string> split(const std::string& s, char delim);

  template <typename K, typename V1, typename V2>
  bool keys_subset(const std::string& a_name,
                   const std::unordered_map<K, V1>& a,
                   const std::string& b_name,
                   const std::unordered_map<K, V2>& b) {
    for (const auto& [id, _] : a) {
      if (!b.contains(id)) {
        std::cerr << "id " << id << " in " << a_name
                  << " not found in " << b_name << std::endl;
        return false;
      }
    }
    return true;
  }
}  // namespace util
