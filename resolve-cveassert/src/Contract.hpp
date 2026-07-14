/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Remediation.hpp"
#include <vector>

enum class PredicateKind {
  InBounds,
  NotEqual,
  NotNull,
  NonZero,
};

// Predicates tell the compiler what
// must be true before executing the operation
struct Precondition {
  PredicateKind kind;
  unsigned arg0;
  unsigned arg1;
};

struct Contract {
  std::vector<Precondition> preconditions;
  RemediationStrategies strategy;
};
