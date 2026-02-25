/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <string>
#include <vector>

#include "reach/util.hpp"

using namespace std;

namespace util {
  // Split string by single character delimiter.
  // https://stackoverflow.com/a/46931770
  vector<string> split(const string& s, char delim) {
    vector<string> result;
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
      result.push_back(item);
    }
    return result;
  }
}  // namespace util
