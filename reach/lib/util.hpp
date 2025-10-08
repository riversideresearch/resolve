#pragma once

#include <functional>
#include <optional>
#include <sstream>

#define AT(map, key) util::at(map, key, #map)

namespace util {
  template <typename K, typename V>
  inline V at(const std::unordered_map<K, V>& m, const K& k, const std::string& msg) {
    try {
      return m.at(k);
    }
    catch (...) {
      std::stringstream ss;
      ss << msg << ": key " << k << " not found";
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

  std::optional<std::string> name_of_id(const std::string& id);
}
