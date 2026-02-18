/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

#include "llvm/IR/Function.h"
#include <string>
void sanitizeUndesirableOperationInFunction(llvm::Function *F,
                                            std::string fnName,
                                            unsigned int argNum);