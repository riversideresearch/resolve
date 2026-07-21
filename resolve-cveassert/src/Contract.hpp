/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "llvm/Support/JSON.h"

#include <vector>

enum class PredicateKind {
  InBounds,
  NotEqual,
  NotNull,
  NonZero,
};

// Predicates tell the compiler what
// must be true before executing the operation
struct Predicate {
  PredicateKind kind;
  unsigned arg0;
  unsigned arg1;
};

struct Contract {
  std::vector<Predicate> preconditions;
};
