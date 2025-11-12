/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#pragma once

#include <deque>
#include <unordered_set>

template <class T, class Hash = std::hash<T>, class Eq = std::equal_to<T>>
class Worklist {
public:
  Worklist() = default;

  Worklist(std::initializer_list<T> init) {
    push_unique_range(init.begin(), init.end());
  }

  template <class It> Worklist(It first, It last) {
    push_unique_range(first, last);
  }

  bool push_unique(const T &x) {
    if (!seen.insert(x).second)
      return false;
    dq.push_back(x);
    return true;
  }

  template <class It> void push_unique_range(It first, It last) {
    for (; first != last; ++first)
      push_unique(*first);
  }

  bool empty() const { return dq.empty(); }

  T pop() {
    T x = dq.front();
    dq.pop_front();
    return x;
  }

private:
  std::deque<T> dq;
  std::unordered_set<T, Hash, Eq> seen;
};
