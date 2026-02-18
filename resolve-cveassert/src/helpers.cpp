/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include "CVEAssert.hpp"
#include "Vulnerability.hpp"
#include "helpers.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>

using namespace llvm;

std::string getLLVMType(Type *ty) {
  // TODO: This is going to be super slow, may want to cache the computed
  // strings
  // TODO: Add mitigations to prevent really large symbol lengths
  auto escapeTypeToIdent = [](const std::string &s) {
    auto isIdentChar = [](char c) {
      return (c == '_') || std::isalnum(static_cast<unsigned char>(c));
    };

    std::string out;
    out.reserve(s.size() * 3 + 3);
    out += "ty_"; // safe prefix
    for (unsigned char c : s) {
      if (isIdentChar(c)) {
        if (c == '_') {
          out += "_5f"; // escape underscore itself
        } else {
          out += c;
        }
      } else {
        std::ostringstream oss;
        oss << '_' << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(c);
        out += oss.str();
      }
    }
    return out;
  };
  std::string canon;
  llvm::raw_string_ostream rso(canon);
  ty->print(rso);
  rso.flush();

  return escapeTypeToIdent(canon);
}

Function *getOrCreateIsHeap(Module *M, LLVMContext &Ctx) {
  std::string handlerName = "resolve_is_heap";

  if (auto handler = M->getFunction(handlerName))
    return handler;

  IRBuilder<> Builder(Ctx);
  // TODO: handle address spaces other than 0
  auto ptr_ty = PointerType::get(Ctx, 0);

  // TODO: write this in asm as some kind of sanitzer_rt?
  FunctionType *FuncType =
      FunctionType::get(Type::getIntNTy(Ctx, 1), {ptr_ty}, false);
  Function *sanitizeFn =
      Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", sanitizeFn);
  Builder.SetInsertPoint(Entry);

  // Get function argument
  Argument *InputPtr = sanitizeFn->getArg(0);

  FunctionType *AsmType = FunctionType::get(ptr_ty, {});
  auto read_sp_asm = InlineAsm::get(AsmType, "mov %rsp, $0",
                                    "=r,~{dirflag},~{fpsr},~{flags}", true);
  auto read_sp = Builder.CreateCall(read_sp_asm, {});
  // ($rsp <= InputPtr)
  auto is_stack = Builder.CreateICmpULE(read_sp, InputPtr);

  auto start = M->getOrInsertGlobal("_start", Type::getInt8Ty(Ctx));
  auto end = M->getOrInsertGlobal("_end", Type::getInt8Ty(Ctx));

  // ((InputPtr >= _start) && (InputPtr <= _end))
  auto is_static = Builder.CreateAnd({
      Builder.CreateICmpUGE(InputPtr, start),
      Builder.CreateICmpULE(InputPtr, end),
  });

  // return !(is_stack || is_static);
  auto result = Builder.CreateNot(Builder.CreateOr({is_stack, is_static}));
  Builder.CreateRet(result);

  raw_ostream &out = errs();
  out << *sanitizeFn;
  if (verifyFunction(*sanitizeFn, &out)) {
  }

  return sanitizeFn;
}

Function *getOrCreateResolveReportSanitizerTriggered(Module *M) {
  auto &Ctx = M->getContext();
  auto void_ty = Type::getVoidTy(Ctx);

  FunctionType *resolve_report_fn_ty = FunctionType::get(void_ty, {}, false);

  if (Function *F = M->getFunction("resolve_report_sanitizer_triggered"))
    if (!F->isDeclaration())
      return F;

  Function *resolve_report_fn =
      Function::Create(resolve_report_fn_ty, GlobalValue::WeakAnyLinkage,
                       "resolve_report_sanitizer_triggered", M);

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "", resolve_report_fn);
  IRBuilder<> builder(EntryBB);
  builder.CreateRetVoid();

  raw_ostream &out = errs();
  out << *resolve_report_fn;
  if (verifyFunction(*resolve_report_fn, &out)) {
  }
  return resolve_report_fn;
}

Function *getOrCreateRecoverBufferFunction(Module *M) {
  if (Function *F = M->getFunction("resolve_get_recover_longjmp_buf"))
    if (!F->isDeclaration())
      return F;

  auto ptr_ty = PointerType::get(M->getContext(), 0);
  FunctionType *resolve_recover_buf_fn_ty =
      FunctionType::get(ptr_ty, {}, false);

  auto recover_buf_fn =
      Function::Create(resolve_recover_buf_fn_ty, GlobalValue::WeakAnyLinkage,
                       "resolve_get_recover_longjmp_buf", M);

  BasicBlock *EntryBB = BasicBlock::Create(M->getContext(), "", recover_buf_fn);
  IRBuilder<> builder(EntryBB);
  builder.SetInsertPoint(EntryBB);
  builder.CreateRet(Constant::getNullValue(ptr_ty));

  raw_ostream &out = errs();
  out << *recover_buf_fn;
  if (verifyFunction(*recover_buf_fn, &out)) {
  }

  return recover_buf_fn;
}

// getOrCreateRemediateBehavior: helper function to apply remediation strategies
Function *
getOrCreateRemediationBehavior(Module *M,
                               Vulnerability::RemediationStrategies strategy) {
  auto &Ctx = M->getContext();
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto void_ty = Type::getVoidTy(Ctx);
  auto i32_ty = Type::getInt32Ty(Ctx);

  FunctionType *resolve_remed_behavior_ty =
      FunctionType::get(void_ty, {}, false);
  if (Function *F = M->getFunction("resolve_remediation_behavior"))
    if (!F->isDeclaration())
      return F;

  Function *resolve_remed_behavior =
      Function::Create(resolve_remed_behavior_ty, GlobalValue::InternalLinkage,
                       "resolve_remediation_behavior", M);

  BasicBlock *BB = BasicBlock::Create(Ctx, "", resolve_remed_behavior);
  IRBuilder<> Builder(BB);

  if (strategy == Vulnerability::RemediationStrategies::EXIT) {
    // void exit(i32)
    FunctionType *exitTy =
        FunctionType::get(void_ty, {Type::getInt32Ty(Ctx)}, false);

    FunctionCallee exitFn = M->getOrInsertFunction("exit", exitTy);
    Value *exitCode = Builder.getInt32(3);
    Builder.CreateCall(exitFn, {exitCode});

  } else if (strategy == Vulnerability::RemediationStrategies::RECOVER) {
    // void longjmp(void buf[], int val)
    FunctionCallee longjmpFn = M->getOrInsertFunction(
        "longjmp", FunctionType::get(void_ty, {ptr_ty, i32_ty}, false));

    // NOTE: resolve_get_recover_longjmp_buf must exist in C source code
    Function *resolve_recover_buf_fn = getOrCreateRecoverBufferFunction(M);

    Value *resolve_longjmp_ptr = Builder.CreateCall(resolve_recover_buf_fn);
    Value *longjmpVal = ConstantInt::get(i32_ty, 42);
    Builder.CreateCall(longjmpFn, {resolve_longjmp_ptr, longjmpVal});
  }
  Builder.CreateRetVoid();

  raw_ostream &out = errs();
  out << *resolve_remed_behavior;
  if (verifyFunction(*resolve_remed_behavior, &out)) {
  }
  return resolve_remed_behavior;
}