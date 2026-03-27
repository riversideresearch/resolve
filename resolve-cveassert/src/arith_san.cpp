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

#include <deque>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;

void sanitizeBitShift(Function *F,
                      Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);
  std::vector<Instruction *> worklist;

  switch (strategy) {
  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
    break;

  default:
    llvm::errs() << "[CVEAssert] Error: sanitizeBitShift does not support "
                 << " remediation strategy defaulting to EXIT strategy!\n";
    strategy = Vulnerability::RemediationStrategies::EXIT;
    break;
  }

  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
        switch (BinOp->getOpcode()) {
        case Instruction::Shl:
        case Instruction::AShr:
        case Instruction::LShr: {
          worklist.push_back(BinOp);
        }

        default:
          continue;
        }
      }
    }
  }

  for (auto *binary_inst : worklist) {
    Value *IsNegative = nullptr;
    Value *IsGreaterThanBitWidth = nullptr;
    Value *CheckShiftAmtCond = nullptr;

    builder.SetInsertPoint(binary_inst);
    Value *shifted_value = binary_inst->getOperand(0);
    Value *shift_amt = binary_inst->getOperand(1);
    unsigned BitWidth = shifted_value->getType()->getIntegerBitWidth();

    IsNegative = builder.CreateICmpULT(
        shift_amt, ConstantInt::get(shift_amt->getType(), 0));
    IsGreaterThanBitWidth = builder.CreateICmpUGE(
        shift_amt, ConstantInt::get(shift_amt->getType(), BitWidth));
    CheckShiftAmtCond = builder.CreateOr(IsNegative, IsGreaterThanBitWidth);

    BasicBlock *originalBB = binary_inst->getParent();
    BasicBlock *joinResultBB = originalBB->splitBasicBlock(binary_inst);
    BasicBlock *preserveShiftBB = BasicBlock::Create(Ctx, "", F, joinResultBB);
    BasicBlock *remedShiftBB = BasicBlock::Create(Ctx, "", F, joinResultBB);

    // originalBB: Branch if the shift amount is negative or greater than
    // bitwidth
    builder.SetInsertPoint(originalBB->getTerminator());
    builder.CreateCondBr(CheckShiftAmtCond, remedShiftBB, preserveShiftBB);
    originalBB->getTerminator()->eraseFromParent();

    // remedShiftBB: Perform safe shift operation
    builder.SetInsertPoint(remedShiftBB);
    builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    Value *safeShift = nullptr;
    Value *safeShiftAmt;

    switch (binary_inst->getOpcode()) {
    case Instruction::Shl:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = builder.CreateShl(shifted_value, safeShiftAmt);
      break;

    case Instruction::AShr:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = builder.CreateAShr(shifted_value, safeShiftAmt);
      break;

    case Instruction::LShr:
      safeShiftAmt = ConstantInt::get(shift_amt->getType(), 0);
      safeShift = builder.CreateLShr(shifted_value, safeShiftAmt);
      break;
    }

    builder.CreateBr(joinResultBB);

    // preserveShiftBB: Preserve shift operation if unaffected
    builder.SetInsertPoint(preserveShiftBB);
    Value *normalResult = nullptr;

    switch (binary_inst->getOpcode()) {
    case Instruction::Shl:
      normalResult = builder.CreateShl(shifted_value, shift_amt);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::AShr:
      normalResult = builder.CreateAShr(shifted_value, shift_amt);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::LShr:
      normalResult = builder.CreateLShr(shifted_value, shift_amt);
      builder.CreateBr(joinResultBB);
      break;
    }

    // joinResultBB: Collect results from control flow using phi
    builder.SetInsertPoint(&*joinResultBB->begin());
    PHINode *phi_instr = builder.CreatePHI(binary_inst->getType(), 2);
    phi_instr->addIncoming(safeShift, remedShiftBB);
    phi_instr->addIncoming(normalResult, preserveShiftBB);

    // Replace all shift operations with phi
    binary_inst->replaceAllUsesWith(phi_instr);

    // Erase old shift operation
    binary_inst->eraseFromParent();
  }
}

void sanitizeDivideByZero(Function *F,
                          Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  auto usize_ty = Type::getInt64Ty(Ctx);
  IRBuilder<> builder(Ctx);
  std::vector<Instruction *> worklist;

  switch (strategy) {
  case Vulnerability::RemediationStrategies::CONTINUE:
  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::RECOVER:
    break;

  default:
    llvm::errs() << "[CVEAssert] Error: sanitizeDivideByZero does not support "
                 << " remediation strategy defaulting to continue strategy!\n";
    strategy = Vulnerability::RemediationStrategies::CONTINUE;
    break;
  }

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
  for (auto *binary_inst : worklist) {
    Value *dividend;
    Value *divisor;
    Value *isZero;

    // checkMapEntryBB
    // checkZeroBB
    // preserveDivBB
    // remedDivBB
    // joinResultBB

    BasicBlock *checkMapEntryBB = binary_inst->getParent();
    BasicBlock *joinResultBB = checkMapEntryBB->splitBasicBlock(binary_inst);
    BasicBlock *checkZeroBB = BasicBlock::Create(Ctx, "check_zero", F);
    BasicBlock *preserveDivBB = BasicBlock::Create(Ctx, "preserve_division", F, joinResultBB);
    BasicBlock *remedDivBB = BasicBlock::Create(Ctx, "remediate_division", F, joinResultBB);

    checkMapEntryBB->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(checkMapEntryBB);
    Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M), { ConstantInt::get(usize_ty, 3)});
    Value *isMapEntryZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(usize_ty, 0));
    builder.CreateCondBr(isZero, preserveDivBB, checkZeroBB);

    builder.SetInsertPoint(checkZeroBB);

    // Extract dividend and divisor
    dividend = binary_inst->getOperand(0);
    divisor = binary_inst->getOperand(1);

    // Check opcode of instruction
    switch (binary_inst->getOpcode()) {
    case Instruction::SDiv:
    case Instruction::UDiv:
    case Instruction::SRem:
    case Instruction::URem:
      isZero = builder.CreateICmpEQ(divisor,
                                    ConstantInt::get(divisor->getType(), 0));
      break;
    case Instruction::FDiv:
    case Instruction::FRem:
      isZero = builder.CreateFCmpOEQ(divisor,
                                     ConstantFP::get(divisor->getType(), 0.0));
      break;
    }

    builder.CreateCondBr(isZero, remedDivBB, preserveDivBB);

    // remedDivBB: Perform safe division
    builder.SetInsertPoint(remedDivBB);
    builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    Value *safeDiv = nullptr;
    Value *safeIntDivisor;
    Value *safeFpDivisor;

    switch (binary_inst->getOpcode()) {
    case Instruction::UDiv:
      safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
      safeDiv = builder.CreateUDiv(dividend, safeIntDivisor);
      break;

    case Instruction::SDiv:
      safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
      safeDiv = builder.CreateSDiv(dividend, safeIntDivisor);
      break;

    case Instruction::FDiv:
      safeFpDivisor = ConstantFP::get(binary_inst->getType(), 1.0);
      safeDiv = builder.CreateFDiv(dividend, safeFpDivisor);
      break;

    case Instruction::URem:
      safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
      safeDiv = builder.CreateURem(dividend, safeIntDivisor);
      break;

    case Instruction::SRem:
      safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
      safeDiv = builder.CreateSRem(dividend, safeIntDivisor);
      break;

    case Instruction::FRem:
      safeFpDivisor = ConstantFP::get(divisor->getType(), 1.0);
      safeDiv = builder.CreateFRem(dividend, safeFpDivisor);
      break;
    }

    builder.CreateBr(joinResultBB);

    // Build preserveDivBB: Preserve division if case is unaffected
    builder.SetInsertPoint(preserveDivBB);
    Value *normalResult = nullptr;

    switch (binary_inst->getOpcode()) {
    case Instruction::SDiv:
      normalResult = builder.CreateSDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::UDiv:
      normalResult = builder.CreateUDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::FDiv:
      normalResult = builder.CreateFDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::SRem:
      normalResult = builder.CreateSRem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::URem:
      normalResult = builder.CreateURem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::FRem:
      normalResult = builder.CreateFRem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;
    }

    // joinResultBB: Collect results from both control flow branchs using phi
    builder.SetInsertPoint(&*joinResultBB->begin());
    PHINode *phi_instr = builder.CreatePHI(binary_inst->getType(), 2);
    phi_instr->addIncoming(safeDiv, remedDivBB);
    phi_instr->addIncoming(normalResult, preserveDivBB);

    // Replace uses of original division with phi
    binary_inst->replaceAllUsesWith(phi_instr);

    // Erase old division
    binary_inst->eraseFromParent();
  }
}

static void widenIntOverflow(Function *F) {
  // Basic algorithm:
  // Find the pattern of overflowing op -> sext
  // Replace with sext -> overflowing op
  // Repeat until fixpoint

  std::deque<CastInst *> worklist;

  // initialize worklist with all sext's
  for (auto &BB : *F) {
    for (auto &instr : BB) {
      if (auto *CastOp = dyn_cast<CastInst>(&instr)) {
        if (CastOp->getOpcode() == Instruction::SExt) {
          worklist.push_back(CastOp);
        }
      }
    }
  }

  // Cast to BinOp if this is an overflowing arith operation.
  auto asArithOp = [](Value *val) -> BinaryOperator * {
    if (auto *BinOp = dyn_cast<BinaryOperator>(val)) {
      if (BinOp->getOpcode() == Instruction::Add ||
          BinOp->getOpcode() == Instruction::Sub ||
          BinOp->getOpcode() == Instruction::Mul) {
        return BinOp;
      }
    }
    return nullptr;
  };

  // for sext in worklist.pop:
  //    // if not sext.arg(0).'could_overflow': continue
  //    // make a new sext for op's args
  //    // make a new op with the widen'd types
  //    // replace all uses of sext with the new widened op
  //    // add new sext to worklist
  while (worklist.size()) {
    auto *cast = worklist.front();
    worklist.pop_front();
    // Is this a sign extension of an overflowing op?
    auto *arith = asArithOp(cast->getOperand(0));
    if (arith == nullptr)
      continue;

    // Bubble up the sign extension and widen the operation...
    auto widenTy = cast->getDestTy();
    IRBuilder<> builder(arith->getNextNode());
    CastInst *sextA = (CastInst *)builder.CreateCast(
        cast->getOpcode(), arith->getOperand(0), widenTy);
    CastInst *sextB = (CastInst *)builder.CreateCast(
        cast->getOpcode(), arith->getOperand(1), widenTy);
    auto widenedOp = builder.CreateBinOp(arith->getOpcode(), sextA, sextB);

    // add new sext's to worklist
    // FIXME: Why doesn't this work?
    // worklist.push_back((CastInst*)sextA);
    // worklist.push_back((CastInst*)sextB);

    // replace this sext with the widened op
    cast->replaceAllUsesWith(widenedOp);
    cast->eraseFromParent();
  }
}

void sanitizeIntOverflow(Function *F,
                         Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

  auto usize_ty = Type::getInt64Ty(Ctx);

  switch (strategy) {
  case Vulnerability::RemediationStrategies::WIDEN:
    return widenIntOverflow(F);

  case Vulnerability::RemediationStrategies::RECOVER:
  case Vulnerability::RemediationStrategies::EXIT:
  case Vulnerability::RemediationStrategies::WRAP:
  case Vulnerability::RemediationStrategies::SAT:
    break;

  default:
    llvm::errs()
        << "[CVEAssert] Error: sanitizeIntOverflow does not support "
           "remediation strategy specified defaulting to wrap strategy!\n";
    strategy = Vulnerability::RemediationStrategies::WRAP;
    break;
  }

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

  Value *op1;
  Value *op2;

  for (auto *binary_inst : worklist) {
    if (!binary_inst->hasNoSignedWrap() && !binary_inst->hasNoUnsignedWrap()) {
      continue;
    }

    op1 = binary_inst->getOperand(0);
    op2 = binary_inst->getOperand(1);

    builder.SetInsertPoint(binary_inst);

    auto insertSafeOp = [&builder,
                         M](Instruction *binary_inst, Value *op1,
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
      Value *safeCall = builder.CreateCall(safeOp, {op1, op2});
      Value *result = builder.CreateExtractValue(safeCall, 0);
      Value *isOverflow = builder.CreateExtractValue(safeCall, 1);

      return {result, isOverflow};
    };

    auto insertSatOp = [&builder, M](Instruction *binary_inst, Value *op1,
                                     Value *op2) -> Instruction * {
      Intrinsic::ID intrinsic_id;
      Type *BinOpType = binary_inst->getType();
      bool isUnsigned = false;

      if (binary_inst->hasNoUnsignedWrap() && !binary_inst->hasNoSignedWrap()) {
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

      // Add fracBits parameter for saturated multiplication operations
      // LLVM LangRef:
      // https://llvm.org/docs/LangRef.html#fixed-point-arithmetic-intrinsics
      if (binary_inst->getOpcode() == Instruction::Mul) {
        Value *fracBits = ConstantInt::get(BinOpType, 0);
        return builder.CreateCall(satOp, {op1, op2, fracBits});

      } else {
        return builder.CreateCall(satOp, {op1, op2});
      }
    };

    auto [safeResult, isOverflow] = insertSafeOp(binary_inst, op1, op2);
    auto satResult = insertSatOp(binary_inst, op1, op2);

    // checkMapEntryBB
    // checkZeroBB
    // preserveDivBB
    // remedDivBB
    // joinResultBB
    BasicBlock *checkMapEntryBB = binary_inst->getParent();
    BasicBlock *joinResultBB = checkMapEntryBB->splitBasicBlock(binary_inst);
    BasicBlock *checkOverflowBB = BasicBlock::Create(Ctx, "check_overflow", F);
    BasicBlock *remedOverflowBB = BasicBlock::Create(Ctx, "remediate_overflow", F, joinResultBB);

    checkMapEntryBB->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(checkMapEntryBB);
    Value *mapEntry = builder.CreateCall(getOrCreateSanitizerMapEntry(M), { ConstantInt::get(usize_ty, 3)});
    Value *isMapEntryZero = builder.CreateICmpEQ(mapEntry, ConstantInt::get(usize_ty, 0));
    builder.CreateCondBr(isMapEntryZero, joinResultBB, checkOverflowBB);

    builder.SetInsertPoint(checkOverflowBB);
    builder.CreateCondBr(isOverflow, remedOverflowBB, joinResultBB);

    // remedOverflowBB: Call resolve_remediation_behavior
    builder.SetInsertPoint(remedOverflowBB);
    builder.CreateCall(getOrCreateResolveReportSanitizerTriggered(M));
    builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    builder.CreateBr(joinResultBB);

    // joinResultBB: resume control flow execution
    builder.SetInsertPoint(&*joinResultBB->begin());
    if (strategy == Vulnerability::RemediationStrategies::SAT) {
      binary_inst->replaceAllUsesWith(satResult);
    } else {
      binary_inst->replaceAllUsesWith(safeResult);
    }

    binary_inst->eraseFromParent();
  }
}