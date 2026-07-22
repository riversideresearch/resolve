/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "Contract.hpp"
#include "Remediation.hpp"
#include "llvm/IR/Function.h"
#include <string>
void sanitizeContract(llvm::Function *F, Contract contract,
                      RemediationStrategies policy);
