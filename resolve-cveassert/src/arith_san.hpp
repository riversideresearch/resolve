/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once

#include "llvm/IR/Function.h"
#include "Vulnerability.hpp"
void sanitizeDivideByZero(llvm::Function *F, Vulnerability::RemediationStrategies strategy);
void sanitizeIntOverflow(llvm::Function *F, Vulnerability::RemediationStrategies strategy);
void sanitizeBitShift(llvm::Function *F, Vulnerability::RemediationStrategies strategy);
