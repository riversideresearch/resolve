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
<<<<<<< HEAD
void instrumentMalloc(llvm::Function *F);
void instrumentRealloc(llvm::Function *F);
void instrumentCalloc(llvm::Function *F);
=======
void instrumentFree(llvm::Function *F);
>>>>>>> e5efcc5 (bounds_check.cpp: Added helper functions to instrument 'free' function callsites.)
void sanitizeMemInstBounds(llvm::Function *F, Vulnerability::RemediationStrategies strategy);