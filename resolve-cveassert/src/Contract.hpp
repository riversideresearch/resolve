/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

enum class PredicateKind {
  InBounds,
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
  llvm::StringRef operation;
  std::vector<Precondition> preconditions;
};
