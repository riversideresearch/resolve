#include <chrono>

#include "util.hpp"

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

  optional<string> name_of_id(const string& id) {
    const auto toks = util::split(id, ':');
    if (!toks.size()) {
      return {};
    }
    return toks.back();
  }
}
