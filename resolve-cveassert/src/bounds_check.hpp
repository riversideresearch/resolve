/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Vulnerability.hpp"
#include "llvm/IR/Function.h"
void sanitizeLoadStore(llvm::Function *F,
                       Vulnerability::RemediationStrategies strategy);
void sanitizeMemcpy(llvm::Function *F,
                    Vulnerability::RemediationStrategies strategy);
void sanitizeMemset(llvm::Function *F,
                    Vulnerability::RemediationStrategies strategy);
void sanitizeMemInstBounds(llvm::Function *F,
                           Vulnerability::RemediationStrategies strategy);