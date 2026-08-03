/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Remediation.hpp"
#include "llvm/IR/Function.h"
void sanitizeDivideByZero(llvm::Function *F, RemediationStrategies strategy);
void sanitizeIntOverflow(llvm::Function *F, RemediationStrategies strategy);
void sanitizeBitShift(llvm::Function *F, RemediationStrategies strategy);
