/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "Vulnerability.hpp"

#include <vector>
#include <string>

using namespace llvm;

Function *replaceUndesirableFunction(unsigned int arg, std::string cond) {

}

void sanitizeUndesirableOperationInFunction(Function *F, Vulnerability::RemediationStrategies strategy,
                                    std::optional<std::string> funct_name) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  // Container to store call insts
  std::vector<CallInst> callsToReplace;
  
  // Container stores affected function args
  std::vector<Value *> fnArgs;

  // loop over each basic block in the vulnerable function
  for (auto &BB : *F) {
    // loop over each instruction
    for (auto &inst : BB) {
      if (auto *call = dyn_cast<CallInst>(&inst)) {
        Function *calledFunc = call->getCalledFunction();
        if (!calledFunc) {
          continue;
        }

        StringRef calledFuncName = calledFunc->getName();
        if (calledFuncName == *funct_name) {
          callsToReplace.push_back(call);
        }
      }
    }
  }

  if (callsToReplace.size() == 0) {
    return;
  }
  
  // Construct the resolve_sanitize_func function
  Function *resolveSanitizedFn = replaceUndesirableFunction(F, strategy, callsToReplace.front());

  // Replace calls at all callsites in the module
  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);

    // Recreate argument list
    

    for (unsigned i = 0; i < call->arg_size(); ++i) {
        fnArgs.push_back(call->getOperand(i));
    }

    auto sanitizedCall = builder.CreateCall(resolveSanitizedFn, fnArgs);

    // replace all callsites
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}