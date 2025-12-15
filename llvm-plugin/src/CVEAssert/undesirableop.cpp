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

using namespace llvm;

void sanitizeUndesirableOperationInFunction(Function *F, Vulnerability::RemediationStrategies strategy,
                                    std::optional<std::string> funct_name) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  // Container to store call insts
  SmallVector<CallInst *, 4> callsToReplace;

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
  Function *resolve_sanitized_func = replaceUndesirableFunction(F, strategy, callsToReplace.front());

  // Replace calls at all callsites in the module
  for (auto call : callsToReplace) {
    builder.SetInsertPoint(call);

    // Recreate argument list
    SmallVector<Value *, 2> fnArgs;

    for (unsigned i = 0; i < call->arg_size(); ++i) {
        fnArgs.push_back(call->getOperand(i));
    }

    auto sanitizedCall = builder.CreateCall(resolveSanitizedFn, fnArgs);

    // replace all callsites
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}


  // Handle calls at each point in module
//   for (auto call : callsToReplace) {
//     // Set the insertion point befoore call instruction.
//     Builder.SetInsertPoint(call);

//     // Recreate argument list
//     SmallVector<Value *, > func_args;
//     for (unsigned i = 0; i < call->arg_size(); ++i) {
//       func_args.push_back(call->getOperand(i));
//     }

//     auto sanitizedCall = Builder.CreateCall(resolve_sanitized_func, func_args);

//     // replace old uses with new call
//     call->replaceAllUsesWith(sanitizedCall);
//     call->eraseFromParent();
//   }