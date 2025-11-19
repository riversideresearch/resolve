/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "CVEAssert.hpp"
#include "Vulnerability.hpp"
#include "arith_san.hpp"
#include "helpers.hpp"


#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;

void sanitizeBinShift(Function *F) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
        switch (BinOp->getOpcode()) {
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr: {
          worklist.push_back(BinOp);
        }
        }
      }
    }
  }

  for (auto *binary_instr : worklist) {
    Builder.SetInsertPoint(binary_instr);

    Value *shifted_value = binary_instr->getOperand(0);
    Value *shift_amt = binary_instr->getOperand(1);

    unsigned BitWidth = shifted_value->getType()->getIntegerBitWidth();
    Value *IsNegative = nullptr;
    Value *IsGreaterThanBitWidth = nullptr;
    Value *CheckShiftAmtCond = nullptr;

    IsNegative = Builder.CreateICmpULT(
        shift_amt, ConstantInt::get(shift_amt->getType(), 0));
    IsGreaterThanBitWidth = Builder.CreateICmpUGE(
        shift_amt, ConstantInt::get(shift_amt->getType(), BitWidth));
    CheckShiftAmtCond = Builder.CreateOr(IsNegative, IsGreaterThanBitWidth);

    BasicBlock *originalBB = binary_instr->getParent();
    BasicBlock *contExeBB = originalBB->splitBasicBlock(binary_instr);
    BasicBlock *preserveShiftBB = BasicBlock::Create(Ctx, "", F, contExeBB);
    BasicBlock *remedShiftBB = BasicBlock::Create(Ctx, "", F, contExeBB);

    // originalBB: Branch if the shift amount is negative or greater than
    // bitwidth
    Builder.SetInsertPoint(originalBB->getTerminator());
    Builder.CreateCondBr(CheckShiftAmtCond, remedShiftBB, preserveShiftBB);
    originalBB->getTerminator()->eraseFromParent();

    // remedShiftBB: Perform safe shift operation
    Builder.SetInsertPoint(remedShiftBB);
    Builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
    Value *safeShift = nullptr;
    Value *safeShiftAmt;

    switch (binary_instr->getOpcode()) {
    case Instruction::Shl:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = Builder.CreateShl(shifted_value, safeShiftAmt);
      break;

    case Instruction::AShr:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = Builder.CreateAShr(shifted_value, safeShiftAmt);
      break;

    case Instruction::LShr:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = Builder.CreateLShr(shifted_value, safeShiftAmt);
      break;
    }

    Builder.CreateBr(contExeBB);

    // preserveShiftBB: Preserve shift operation if unaffected
    Builder.SetInsertPoint(preserveShiftBB);
    Value *normalResult = nullptr;

    switch (binary_instr->getOpcode()) {
    case Instruction::Shl:
      normalResult = Builder.CreateShl(shifted_value, shift_amt);
      Builder.CreateBr(contExeBB);
      break;

    case Instruction::AShr:
      normalResult = Builder.CreateAShr(shifted_value, shift_amt);
      Builder.CreateBr(contExeBB);
      break;

    case Instruction::LShr:
      normalResult = Builder.CreateLShr(shifted_value, shift_amt);
      Builder.CreateBr(contExeBB);
      break;
    }

    // contExeBB: Collect results from control flow using phi
    Builder.SetInsertPoint(&*contExeBB->begin());
    PHINode *phi_instr = Builder.CreatePHI(binary_instr->getType(), 2);
    phi_instr->addIncoming(safeShift, remedShiftBB);
    phi_instr->addIncoming(normalResult, preserveShiftBB);

    // Replace all shift operations with phi
    binary_instr->replaceAllUsesWith(phi_instr);

    // Erase old shift operation
    binary_instr->eraseFromParent();
  }
}

void sanitizeDivideByZero(Function *F,  Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

  if (strategy == Vulnerability::RemediationStrategies::RECOVER) {
    sanitizeDivideByZeroRecover(F, strategy);
  } else {

    // Loop over each basic block
    for (auto &BB : *F) {
      // Loop over each instruction
      for (auto &instr : BB) {
        // Check if the instruction is a binary operator
        if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
          // Check if the opcode matches sdiv, udiv, fdiv instruction opcode
          if (BinOp->getOpcode() == Instruction::SDiv ||
              BinOp->getOpcode() == Instruction::UDiv ||
              BinOp->getOpcode() == Instruction::FDiv ||
              BinOp->getOpcode() == Instruction::SRem ||
              BinOp->getOpcode() == Instruction::URem ||
              BinOp->getOpcode() == Instruction::FRem) {
            // Add to worklist
            worklist.push_back(BinOp);
          }
        }
      }
    }

    // Loop over each instruction in the list
    for (auto *binary_instr : worklist) {
      // Set the insertion point at the div instruction
      Builder.SetInsertPoint(binary_instr);

      // Extract dividend and divisor
      Value *dividend = binary_instr->getOperand(0);
      Value *divisor = binary_instr->getOperand(1);

      // Compare divisor == 0
      Value *IsZero = nullptr;

      // Check opcode of instruction
      switch (binary_instr->getOpcode()) {
      case Instruction::SDiv:
      case Instruction::UDiv:
      case Instruction::SRem:
      case Instruction::URem: {
        IsZero = Builder.CreateICmpEQ(divisor,
                                      ConstantInt::get(divisor->getType(), 0));
        break;
      }
      case Instruction::FDiv:
      case Instruction::FRem: {
        IsZero = Builder.CreateFCmpOEQ(
            divisor, ConstantFP::get(divisor->getType(), 0.0));
        break;
      }
      }

      // Split the basic block to insert control flow for div checking.
      BasicBlock *originalBB = binary_instr->getParent();
      BasicBlock *contExeBB = originalBB->splitBasicBlock(binary_instr);
      BasicBlock *preserveDivBB = BasicBlock::Create(Ctx, "", F, contExeBB);
      BasicBlock *remedDivBB = BasicBlock::Create(Ctx, "", F, contExeBB);

      // originalBB: Branch if the divisor is zero
      originalBB->getTerminator()->eraseFromParent();
      Builder.SetInsertPoint(originalBB);
      Builder.CreateCondBr(IsZero, remedDivBB, preserveDivBB);

      // remedDivBB: Perform safe division
      Builder.SetInsertPoint(remedDivBB);
      Builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
      Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
      Value *safeDiv = nullptr;
      Value *safeIntDivisor;
      Value *safeFpDivisor;

      switch (binary_instr->getOpcode()) {
      case Instruction::UDiv:
        safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
        safeDiv = Builder.CreateUDiv(dividend, safeIntDivisor);
        break;

      case Instruction::SDiv:
        safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
        safeDiv = Builder.CreateSDiv(dividend, safeIntDivisor);
        break;

      case Instruction::FDiv:
        safeFpDivisor = ConstantFP::get(binary_instr->getType(), 1.0);
        safeDiv = Builder.CreateFDiv(dividend, safeFpDivisor);
        break;

      case Instruction::URem:
        safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
        safeDiv = Builder.CreateURem(dividend, safeIntDivisor);
        break;

      case Instruction::SRem:
        safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
        safeDiv = Builder.CreateSRem(dividend, safeIntDivisor);
        break;

      case Instruction::FRem:
        safeFpDivisor = ConstantFP::get(divisor->getType(), 1.0);
        safeDiv = Builder.CreateFRem(dividend, safeFpDivisor);
        break;
      }

      Builder.CreateBr(contExeBB);

      // Build preserveDivBB: Preserve division if case is unaffected
      Builder.SetInsertPoint(preserveDivBB);
      Value *normalResult = nullptr;

      switch (binary_instr->getOpcode()) {
      case Instruction::SDiv:
        normalResult = Builder.CreateSDiv(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;

      case Instruction::UDiv:
        normalResult = Builder.CreateUDiv(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;

      case Instruction::FDiv:
        normalResult = Builder.CreateFDiv(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;

      case Instruction::SRem:
        normalResult = Builder.CreateSRem(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;

      case Instruction::URem:
        normalResult = Builder.CreateURem(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;

      case Instruction::FRem:
        normalResult = Builder.CreateFRem(dividend, divisor);
        Builder.CreateBr(contExeBB);
        break;
      }

      // contExeBB: Collect results from both control flow branchs using phi
      Builder.SetInsertPoint(&*contExeBB->begin());
      PHINode *phi_instr = Builder.CreatePHI(binary_instr->getType(), 2);
      phi_instr->addIncoming(safeDiv, remedDivBB);
      phi_instr->addIncoming(normalResult, preserveDivBB);

      // Replace uses of original division with phi
      binary_instr->replaceAllUsesWith(phi_instr);

      // Erase old division
      binary_instr->eraseFromParent();
    }
  }
}

void sanitizeDivideByZeroRecover(Function *F, Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();

  auto void_ty = Type::getVoidTy(Ctx);
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i32_ty = Type::getInt32Ty(Ctx);

  FunctionCallee setjmpFunc = M->getOrInsertFunction(
      "setjmp", FunctionType::get(i32_ty, {ptr_ty}, false));

  FunctionCallee longjmpFunc = M->getOrInsertFunction(
      "longjmp", FunctionType::get(void_ty, {ptr_ty, i32_ty}, false));
  // Insert the jmp_buf at the beginning of function
  BasicBlock &originalEntry = F->getEntryBlock();

  // Initialize basic block for setjmp longjmp
  BasicBlock *sjljEntry = BasicBlock::Create(Ctx, "", F, &originalEntry);
  IRBuilder<> entryBuilder(sjljEntry);

  ArrayType *jmpBufArrTy = ArrayType::get(Type::getInt8Ty(Ctx), 200);
  AllocaInst *jmpBufAlloca =
      entryBuilder.CreateAlloca(jmpBufArrTy, nullptr, "jmpbuf");
  Value *jmpBufPtr = entryBuilder.CreateBitCast(jmpBufAlloca, ptr_ty);

  Value *setjmpVal = entryBuilder.CreateCall(setjmpFunc, {jmpBufPtr});
  Value *isInitial =
      entryBuilder.CreateICmpEQ(setjmpVal, ConstantInt::get(i32_ty, 0));

  // recoverBB: calls error handling function when setjmp returns non-zero
  BasicBlock *recoverBB = BasicBlock::Create(Ctx, "", F);
  entryBuilder.CreateCondBr(isInitial, &originalEntry, recoverBB);

  IRBuilder<> recoverBuilder(recoverBB);
  recoverBuilder.CreateCall(getOrCreateRemediationBehavior(M, strategy));

  Type *retTy = F->getReturnType();
  if (retTy->isVoidTy()) {
    recoverBuilder.CreateRetVoid();
  } else if (retTy->isIntegerTy()) {
    // return zero for integer return types
    Constant *zero = Constant::getNullValue(retTy);
    recoverBuilder.CreateRet(zero);
  } else if (retTy->isPointerTy()) {
    // return null for pointer return types
    recoverBuilder.CreateRet(Constant::getNullValue(retTy));
  } else {
    // fallback: return undef (less ideal, but keeps verifier happy)
    recoverBuilder.CreateRet(UndefValue::get(retTy));
  }

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
        if (BinOp->getOpcode() == Instruction::SDiv ||
            BinOp->getOpcode() == Instruction::UDiv ||
            BinOp->getOpcode() == Instruction::FDiv ||
            BinOp->getOpcode() == Instruction::SRem ||
            BinOp->getOpcode() == Instruction::URem ||
            BinOp->getOpcode() == Instruction::FRem) {
          worklist.push_back(BinOp);
        }
      }
    }
  }

  IRBuilder<> Builder(Ctx);
  for (auto *binary_instr : worklist) {
    Builder.SetInsertPoint(binary_instr);

    // Extract divisor
    Value *divisor = binary_instr->getOperand(1);

    // Compare divisor == 0
    Value *IsZero = nullptr;

    // Check opcode of instruction
    switch (binary_instr->getOpcode()) {
    case Instruction::SDiv:
    case Instruction::UDiv:
    case Instruction::SRem:
    case Instruction::URem: {
      IsZero = Builder.CreateICmpEQ(divisor,
                                    ConstantInt::get(divisor->getType(), 0));
      break;
    }
    case Instruction::FDiv:
    case Instruction::FRem: {
      IsZero = Builder.CreateFCmpOEQ(divisor,
                                     ConstantFP::get(divisor->getType(), 0.0));
      break;
    }
    }

    // Split the basic block to insert control flow for div checking.
    BasicBlock *originalBB = binary_instr->getParent();
    BasicBlock *contExeBB = originalBB->splitBasicBlock(binary_instr);
    BasicBlock *remedDivBB = BasicBlock::Create(Ctx, "", F, contExeBB);

    // originalBB: Branch if the divisor is zero
    originalBB->getTerminator()->eraseFromParent();
    Builder.SetInsertPoint(originalBB);
    Builder.CreateCondBr(IsZero, remedDivBB, contExeBB);

    // remedDivBB: Perform longjmp
    Builder.SetInsertPoint(remedDivBB);
    Value *longJmpRetVal = ConstantInt::get(Type::getInt32Ty(Ctx), 42);
    Builder.CreateCall(longjmpFunc, {jmpBufPtr, longJmpRetVal});
    Builder.CreateUnreachable();
  }
}

Function *replaceUndesirableFunction(Function *F, CallInst *call) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

  Function *calledFunc = call->getCalledFunction();
  if (!calledFunc)
    return nullptr;

  // 1. Create the function name and type.
  std::string sanitizedHandlerName = "resolve_sanitized_function";
  
  if (Function* existing = M->getFunction(sanitizedHandlerName)) {
    return existing;
  }

  FunctionType *sanitizedHandlerType = calledFunc->getFunctionType();

  // Create the function object.
  Function *sanitizedHandlerFunc =
      Function::Create(sanitizedHandlerType, Function::InternalLinkage,
                       sanitizedHandlerName, M);

  Function *resolve_report_func =
      getOrCreateResolveReportSanitizerTriggered(M);

  Function::arg_iterator argIter = sanitizedHandlerFunc->arg_begin();
  Value *dividend = argIter++;
  Value *divisor = argIter;

  BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", sanitizedHandlerFunc);
  BasicBlock *SanitizedBB =
      BasicBlock::Create(Ctx, "sanitized_behavior", sanitizedHandlerFunc);
  BasicBlock *ContExeBB =
      BasicBlock::Create(Ctx, "continue_exec", sanitizedHandlerFunc);

  // EntryBB: contains condition instruction and branch
  Builder.SetInsertPoint(EntryBB);

  // Convert the condition into IR
  auto *condition_code =
      Builder.CreateICmpEQ(divisor, ConstantInt::get(divisor->getType(), 0));
  Builder.CreateCondBr(condition_code, SanitizedBB, ContExeBB);

  // SanitizedBB: Calls sanitized behavior for arithmetic sanitization
  // Returns dividend
  Builder.SetInsertPoint(SanitizedBB);
  Builder.CreateCall(resolve_report_func);
  Builder.CreateRet(dividend);

  // ContExec: Makes call to original call instruction and returns that instead.
  Builder.SetInsertPoint(ContExeBB);
  Value *safeDiv = Builder.CreateCall(calledFunc, {dividend, divisor});
  Builder.CreateRet(safeDiv);

  // DEBUGGING
  raw_ostream &out = errs();
  out << *sanitizedHandlerFunc;
  if (verifyFunction(*sanitizedHandlerFunc, &out)) {
  }

  return sanitizedHandlerFunc;
}

void sanitizeDivideByZeroInFunction(Function *F,
                                    std::optional<std::string> funct_name) {
  Module *M = F->getParent();
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

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
  Function *resolve_sanitized_func =
      replaceUndesirableFunction(F, callsToReplace.front());

  // Handle calls at each point in module
  for (auto call : callsToReplace) {
    // Set the insertion point befoore call instruction.
    Builder.SetInsertPoint(call);

    // Recreate argument list
    SmallVector<Value *, 2> func_args;
    for (unsigned i = 0; i < call->arg_size(); ++i) {
      func_args.push_back(call->getOperand(i));
    }

    auto sanitizedCall = Builder.CreateCall(resolve_sanitized_func, func_args);

    // replace old uses with new call
    call->replaceAllUsesWith(sanitizedCall);
    call->eraseFromParent();
  }
}

// Driver function for integer overflow
void sanitizeIntOverflow(Function *F, Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> Builder(Ctx);

  if (strategy == Vulnerability::RemediationStrategies::RECOVER) {
    sanitizeIntOverflowRecover(F, strategy);
  } else {

    for (auto &BB : *F) {
      for (auto &instr : BB) {
        if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
          if (BinOp->getOpcode() == Instruction::Add ||
              BinOp->getOpcode() == Instruction::Sub ||
              BinOp->getOpcode() == Instruction::Mul) {
            worklist.push_back(BinOp);
          }
        }
      }
    }

    for (auto *binary_inst : worklist) {
      if (!binary_inst->hasNoSignedWrap() &&
          !binary_inst->hasNoUnsignedWrap()) {
        continue;
      }

      Value *op1 = binary_inst->getOperand(0);
      Value *op2 = binary_inst->getOperand(1);

      Builder.SetInsertPoint(binary_inst);

      auto insertSafeOp = [&Builder,
                           M](Instruction *binary_inst, Value *op1,
                              Value *op2) -> std::pair<Value *, Value *> {
        Intrinsic::ID intrinsic_id;
        Type *BinOpType = binary_inst->getType();
        bool isUnsigned = false;

        // Heuristic: If instruction has NUW but not NSW then, treat as unsigned
        if (binary_inst->hasNoUnsignedWrap() &&
            !binary_inst->hasNoSignedWrap()) {
          isUnsigned = true;
        }

        switch (binary_inst->getOpcode()) {
        case Instruction::Add:
          intrinsic_id = isUnsigned ? Intrinsic::uadd_with_overflow
                                    : Intrinsic::sadd_with_overflow;
          break;

        case Instruction::Sub:
          intrinsic_id = isUnsigned ? Intrinsic::usub_with_overflow
                                    : Intrinsic::ssub_with_overflow;
          break;

        case Instruction::Mul:
          intrinsic_id = isUnsigned ? Intrinsic::umul_with_overflow
                                    : Intrinsic::smul_with_overflow;
          break;

        default:
          return {nullptr, nullptr}; // Not a handled opcode
        }

        Function *safeOp =
            Intrinsic::getDeclaration(M, intrinsic_id, BinOpType);
        Value *safeCall = Builder.CreateCall(safeOp, {op1, op2});
        Value *result = Builder.CreateExtractValue(safeCall, 0);
        Value *isOverflow = Builder.CreateExtractValue(safeCall, 1);

        return {result, isOverflow};
      };

      auto [safeResult, isOverflow] = insertSafeOp(binary_inst, op1, op2);
      if (!safeResult || !isOverflow) {
        continue;
      }

      BasicBlock *originalBB = binary_inst->getParent();
      BasicBlock *contExeBB = originalBB->splitBasicBlock(binary_inst);
      BasicBlock *remedOverflowBB = BasicBlock::Create(Ctx, "", F, contExeBB);

      // originalBB: Branch if overflow flag is set
      originalBB->getTerminator()->eraseFromParent();
      Builder.SetInsertPoint(originalBB);
      Builder.CreateCondBr(isOverflow, remedOverflowBB, contExeBB);

      // remedOverflowBB: Construct saturated instructions
      Builder.SetInsertPoint(remedOverflowBB);
      Builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
      Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));

      auto insertSatOp = [&Builder, M](Instruction *binary_inst, Value *op1,
                                       Value *op2) -> Value * {
        Intrinsic::ID intrinsic_id;
        Type *BinOpType = binary_inst->getType();
        bool isUnsigned = false;

        if (binary_inst->hasNoUnsignedWrap() &&
            !binary_inst->hasNoSignedWrap()) {
          isUnsigned = true;
        }

        switch (binary_inst->getOpcode()) {
        case Instruction::Add:
          intrinsic_id = isUnsigned ? Intrinsic::uadd_sat : Intrinsic::sadd_sat;
          break;

        case Instruction::Sub:
          intrinsic_id = isUnsigned ? Intrinsic::usub_sat : Intrinsic::ssub_sat;
          break;

        case Instruction::Mul:
          intrinsic_id = isUnsigned ? Intrinsic::umul_fix_sat
                                    : // Read LLVM LangRef to understand
                                      // semantics of this instruction
                             Intrinsic::smul_fix_sat;
          break;

        default:
          return nullptr;
        }

        Function *satOp = Intrinsic::getDeclaration(M, intrinsic_id, BinOpType);

        // add fracBits parameter for saturated multiplication operations
        // LLVM LangRef:
        // https://llvm.org/docs/LangRef.html#fixed-point-arithmetic-intrinsics
        if (binary_inst->getOpcode() == Instruction::Mul) {
          Value *fracBits = ConstantInt::get(BinOpType, 0);
          return Builder.CreateCall(satOp, {op1, op2, fracBits});

        } else {
          return Builder.CreateCall(satOp, {op1, op2});
        }
      };

      Value *satResult = insertSatOp(binary_inst, op1, op2);
      Builder.CreateBr(contExeBB);

      // contExeBB: resume control flow execution
      Builder.SetInsertPoint(&*contExeBB->begin());
      PHINode *phi = Builder.CreatePHI(binary_inst->getType(), 2);
      phi->addIncoming(safeResult, originalBB);

      if (strategy == Vulnerability::RemediationStrategies::SAT) {
        phi->addIncoming(satResult, remedOverflowBB);

      } else {
        phi->addIncoming(safeResult, remedOverflowBB);
      }

      // Replace the instructions with phi instruction
      binary_inst->replaceAllUsesWith(phi);

      binary_inst->eraseFromParent();
    }
  }
}

void sanitizeIntOverflowRecover(Function *F, Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();

  auto void_ty = Type::getVoidTy(Ctx);
  auto ptr_ty = PointerType::get(Ctx, 0);
  auto i32_ty = Type::getInt32Ty(Ctx);

  // Create function setjmp and longjmp constructs
  FunctionCallee setjmpFunc = M->getOrInsertFunction(
      "setjmp", FunctionType::get(i32_ty, {ptr_ty}, false));

  FunctionCallee longjmpFunc = M->getOrInsertFunction(
      "longjmp", FunctionType::get(void_ty, {ptr_ty, i32_ty}, false));

  // Insert the jmp_buf at the beginning of the function
  BasicBlock &originalEntry = F->getEntryBlock();

  // setjmp longjmp basic block
  BasicBlock *sjljEntry = BasicBlock::Create(Ctx, "", F, &originalEntry);
  IRBuilder<> entryBuilder(sjljEntry);

  ArrayType *jmpBufArrTy = ArrayType::get(Type::getInt8Ty(Ctx), 200);
  AllocaInst *jmpBufAlloca = entryBuilder.CreateAlloca(jmpBufArrTy, nullptr);
  Value *jmpBufPtr = entryBuilder.CreateBitCast(jmpBufAlloca, ptr_ty);

  Value *setjmpVal = entryBuilder.CreateCall(setjmpFunc, {jmpBufPtr});
  Value *isInitial =
      entryBuilder.CreateICmpEQ(setjmpVal, ConstantInt::get(i32_ty, 0));

  // create recoverBB (called when setjmp returns non-zero)
  BasicBlock *recoverBB = BasicBlock::Create(Ctx, "", F);
  entryBuilder.CreateCondBr(isInitial, &originalEntry, recoverBB);

  IRBuilder<> recoverBuilder(recoverBB);
  recoverBuilder.CreateCall(getOrCreateRemediationBehavior(M, strategy));

  Type *retTy = F->getReturnType();
  if (retTy->isVoidTy()) {
    recoverBuilder.CreateRetVoid();
  } else if (retTy->isIntegerTy()) {
    // return zero for integer return types
    Constant *zero = Constant::getNullValue(retTy);
    recoverBuilder.CreateRet(zero);
  } else if (retTy->isPointerTy()) {
    // return null for pointer return types
    recoverBuilder.CreateRet(Constant::getNullValue(retTy));
  } else {
    // fallback: return undef (less ideal, but keeps verifier happy)
    recoverBuilder.CreateRet(UndefValue::get(retTy));
  }

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
        switch (BinOp->getOpcode()) {
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul: {
          worklist.push_back(BinOp);
          break;
        }
        default:
          break;
        }
      }
    }
  }

  IRBuilder<> Builder(Ctx);

  auto insertSafeOp = [&Builder, M](Instruction *binary_inst, Value *op1,
                                    Value *op2) -> std::pair<Value *, Value *> {
    Intrinsic::ID intrinsic_id;
    Type *BinOpType = binary_inst->getType();
    bool isUnsigned = false;

    // Heuristic: If instruction has NUW but not NSW then, treat as unsigned
    if (binary_inst->hasNoUnsignedWrap() && !binary_inst->hasNoSignedWrap()) {
      isUnsigned = true;
    }

    switch (binary_inst->getOpcode()) {
    case Instruction::Add:
      intrinsic_id = isUnsigned ? Intrinsic::uadd_with_overflow
                                : Intrinsic::sadd_with_overflow;
      break;

    case Instruction::Sub:
      intrinsic_id = isUnsigned ? Intrinsic::usub_with_overflow
                                : Intrinsic::ssub_with_overflow;
      break;

    case Instruction::Mul:
      intrinsic_id = isUnsigned ? Intrinsic::umul_with_overflow
                                : Intrinsic::smul_with_overflow;
      break;

    default:
      return {nullptr, nullptr}; // Not a handled opcode
    }

    Function *safeOp = Intrinsic::getDeclaration(M, intrinsic_id, BinOpType);
    Value *safeCall = Builder.CreateCall(safeOp, {op1, op2});
    Value *result = Builder.CreateExtractValue(safeCall, 0);
    Value *isOverflow = Builder.CreateExtractValue(safeCall, 1);
    return {result, isOverflow};
  };

  for (auto *binary_inst : worklist) {
    if (!binary_inst->hasNoSignedWrap() && !!binary_inst->hasNoUnsignedWrap()) {
      continue;
    }

    Value *op1 = binary_inst->getOperand(0);
    Value *op2 = binary_inst->getOperand(1);

    Builder.SetInsertPoint(binary_inst);

    auto [safeResult, isOverflow] = insertSafeOp(binary_inst, op1, op2);
    if (!safeResult || !isOverflow)
      continue;

    BasicBlock *originalBB = binary_inst->getParent();
    BasicBlock *contExeBB = originalBB->splitBasicBlock(binary_inst);
    BasicBlock *remedOverflowBB = BasicBlock::Create(Ctx, "", F, contExeBB);

    originalBB->getTerminator()->eraseFromParent();
    Builder.SetInsertPoint(originalBB);
    Builder.CreateCondBr(isOverflow, remedOverflowBB, contExeBB);

    Builder.SetInsertPoint(remedOverflowBB);
    Value *longJmpRetVal = ConstantInt::get(Type::getInt32Ty(Ctx), 42);
    Builder.CreateCall(longjmpFunc, {jmpBufPtr, longJmpRetVal});
    Builder.CreateUnreachable();

    Builder.SetInsertPoint(&*contExeBB->getFirstInsertionPt());
    PHINode *phi = Builder.CreatePHI(binary_inst->getType(), 1);
    phi->addIncoming(safeResult, originalBB);

    binary_inst->replaceAllUsesWith(phi);
    binary_inst->eraseFromParent();
  }
}