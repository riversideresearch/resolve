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
void instrumentAlloca(llvm::Function *F);
void instrumentMalloc(llvm::Function *F);
void instrumentRealloc(llvm::Function *F);
void instrumentCalloc(llvm::Function *F);
void instrumentFree(llvm::Function *F);
void instrumentStrdup(llvm::Function *F);
void instrumentStrndup(llvm::Function *F);
void sanitizeMemInstBounds(llvm::Function *F,
                           Vulnerability::RemediationStrategies strategy);