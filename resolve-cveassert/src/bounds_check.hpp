/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Vulnerability.hpp"
#include "llvm/IR/Function.h"
void instrumentLoadStore(llvm::Function *F,
                         Vulnerability::RemediationStrategies strategy);
void instrumentMemcpy(llvm::Function *F,
                      Vulnerability::RemediationStrategies strategy);
void instrumentMemmove(llvm::Function *F,
                       Vulnerability::RemediationStrategies strategy);
void instrumentMemset(llvm::Function *F,
                      Vulnerability::RemediationStrategies strategy);
void sanitizeMemInstBounds(llvm::Function *F,
                           Vulnerability::RemediationStrategies strategy);
