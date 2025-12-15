/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once 

#include "llvm/IR/Function.h"
#include "Vulnerability.hpp"
// Parameters
// 1. Which arguments to return (or zero)
// 2. Which arguments to test (if any)
// 3. Condition to test (equality, <, etc..) NOTE: not needed right now delay
//llvm::Function *replaceUndesirableFunction();

void sanitizeUndesirableOperationInFunction(llvm::Function *F, Vulnerability::RemediationStrategies strategy,
                                    std::optional<std::string> funct_name);