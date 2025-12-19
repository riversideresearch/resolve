/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once

#include "llvm/IR/Function.h"
#include "Vulnerability.hpp"
void sanitizeLoadStore(llvm::Function *F, Vulnerability::RemediationStrategies strategy);
void sanitizeMemcpy(llvm::Function *F, Vulnerability::RemediationStrategies strategy);
void instrumentAlloca(llvm::Function *F);
void instrumentMalloc(llvm::Function *F);
void instrumentRealloc(llvm::Function *F);
void sanitizeMemInstBounds(llvm::Function *F, Vulnerability::RemediationStrategies strategy);