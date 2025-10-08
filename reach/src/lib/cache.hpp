// #pragma once

// #include <fstream>
// #include <unordered_map>
// #include <unordered_set>
// #include <vector>

// namespace cache {
  
//   template <typename T>
//   void save_vector(const std::vector<T>& v, const std::string& path) {
//     std::ofstream f(path);
//     for (const auto& x : v) {
//       f << x << " ";
//     }
//   }

//   template <typename T>
//   std::vector<T> load_vector(const std::string& path) {
//     std::ifstream f(path);
//     if (!f.is_open()) {
//       throw std::runtime_error("file" + path + " not found");
//     }
//     std::vector<T> v;
//     T s;
//     while (f >> s) {
//       v.push_back(s);
//     }
//     f.close();
//     return v;
//   }

//   template <typename T>
//   void save_set(const std::unordered_set<T>& set, const std::string& path) {
//     std::ofstream f(path);
//     for (const auto& x : set) {
//       f << x << " ";
//     }
//   }

//   template <typename T>
//   std::unordered_set<T> load_set(const std::string& path) {
//     std::ifstream f(path);
//     if (!f.is_open()) {
//       throw std::runtime_error("file" + path + " not found");
//     }
//     std::unordered_set<T> set;
//     T s;
//     while (f >> s) {
//       set.insert(s);
//     }
//     f.close();
//     return set;
//   }

//   template <typename K, typename V>
//   void save_map(const std::unordered_map<K, V>& map, const std::string& path) {
//     std::ofstream f(path);
//     for (const auto& [k, v] : map) {
//       f << k << " " << v << std::endl;
//     }
//   }

//   template <typename K, typename V>
//   std::unordered_map<K, V> load_map(const std::string& path) {
//     std::ifstream f(path);
//     if (!f.is_open()) {
//       throw std::runtime_error("file" + path + " not found");
//     }
//     std::unordered_map<K, V> map;
//     K k;
//     V v;
//     while (f >> k >> v) {
//       map.emplace(k, v);
//     }
//     f.close();
//     return map;
//   }
// }
