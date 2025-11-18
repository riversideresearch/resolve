
#pragma once

#include "llvm/IR/Function.h"

void sanitizeNullPointers(llvm::Function *f, std::optional<std::string> strategy);
