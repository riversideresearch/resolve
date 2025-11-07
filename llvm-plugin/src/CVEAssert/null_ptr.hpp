/*
 *   Copyright (c) 2025 Riverside Research.
 *   See LICENSE.txt in the repo root for licensing information.
 */

#pragma once

#include "llvm/IR/Function.h"

void sanitizeNullPointers(llvm::Function *f);
