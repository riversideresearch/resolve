/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Remediation.hpp"
#include "llvm/IR/Function.h"
void sanitizeNullPointers(llvm::Function *F, RemediationStrategies strategy);
