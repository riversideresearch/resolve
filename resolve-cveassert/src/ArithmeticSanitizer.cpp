/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"
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
#include "IRUtils.hpp"
#include "Vulnerability.hpp"

#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;

static Constant *getContinueValue(Instruction *I) {
  Type *Ty = I->getType();

  if (Ty->isIntegerTy()) {
    unsigned bitwidth = Ty->getIntegerBitWidth();

    switch (I->getOpcode()) {
    case Instruction::SDiv:
    case Instruction::SRem:
      return ConstantInt::get(Ty, APInt::getSignedMaxValue(bitwidth));

    case Instruction::UDiv:
    case Instruction::URem:
      return ConstantInt::get(Ty, APInt::getMaxValue(bitwidth));

    default:
      llvm_unreachable("Unsupported integer operation");
    }
  }

  if (Ty->isFloatingPointTy()) {
    return ConstantFP::get(Ty, APFloat::getLargest(Ty->getFltSemantics()));
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

void sanitizeDivideByZero(Function *F,
                          Vulnerability::RemediationStrategies strategy) {
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
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

  // Loop over each instruction in the list
  for (auto *binaryInst : worklist) {
    Value *dividend;
    Value *divisor;
    Value *isZero;

    BasicBlock *checkMapEntryBB = binaryInst->getParent();
    BasicBlock *joinResultBB = checkMapEntryBB->splitBasicBlock(binaryInst);
    BasicBlock *checkZeroBB = BasicBlock::Create(Ctx, "check.zero", F);
    BasicBlock *preserveDivBB =
        BasicBlock::Create(Ctx, "perform.div", F, joinResultBB);
    BasicBlock *remedDivBB =
        BasicBlock::Create(Ctx, "sanitize.div", F, joinResultBB);

    checkMapEntryBB->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(checkMapEntryBB);
    createSanitizerGateBranch(builder, F, SanitizerFlag::DivideByZero,
                              preserveDivBB, checkZeroBB);

    builder.SetInsertPoint(checkZeroBB);

    // Extract dividend and divisor
    dividend = binaryInst->getOperand(0);
    divisor = binaryInst->getOperand(1);

    switch (binaryInst->getOpcode()) {
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

    builder.SetInsertPoint(remedDivBB);

    Value *remedValue = nullptr;
    switch (strategy) {
    case Vulnerability::RemediationStrategies::CONTINUE:
      remedValue = getContinueValue(binaryInst);
      builder.CreateBr(joinResultBB);
      break;

    case Vulnerability::RemediationStrategies::EXIT:
    case Vulnerability::RemediationStrategies::RECOVER:
      builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));

      // EXIT/RECOVER transfer control elsewhere
      builder.CreateUnreachable();
      break;

    // The only remediation policies that work with this sanitizer
    // are CONTINUE, EXIT, and RECOVER.
    // This default case should never be triggered because
    // the beginning of the function checks for the correct
    // sanitizer-policy combination
    default:
      break;
    }

    builder.SetInsertPoint(preserveDivBB);

    Value *divOp = nullptr;
    switch (binaryInst->getOpcode()) {
    case Instruction::SDiv:
      divOp = builder.CreateSDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::SRem:
      divOp = builder.CreateSRem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::UDiv:
      divOp = builder.CreateUDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::URem:
      divOp = builder.CreateURem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::FDiv:
      divOp = builder.CreateFDiv(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::FRem:
      divOp = builder.CreateFRem(dividend, divisor);
      builder.CreateBr(joinResultBB);
      break;
    }

    builder.SetInsertPoint(&*joinResultBB->begin());
    PHINode *phi = builder.CreatePHI(binaryInst->getType(), 2);
    phi->addIncoming(divOp, preserveDivBB);

    if (strategy == Vulnerability::RemediationStrategies::CONTINUE) {
      phi->addIncoming(remedValue, remedDivBB);
    }

    binaryInst->replaceAllUsesWith(phi);
    binaryInst->eraseFromParent();
  }
}

void sanitizeIntOverflow(Function *F,
                         Vulnerability::RemediationStrategies strategy) {
  std::vector<Instruction *> worklist;
  Module *M = F->getParent();
  auto &Ctx = M->getContext();
  IRBuilder<> builder(Ctx);

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

  for (auto *binaryInst : worklist) {
    if (!binaryInst->hasNoSignedWrap() && !binaryInst->hasNoUnsignedWrap()) {
      continue;
    }

    op1 = binaryInst->getOperand(0);
    op2 = binaryInst->getOperand(1);

    builder.SetInsertPoint(binaryInst);

    auto insertSafeOp = [&builder,
                         M](Instruction *binaryInst, Value *op1,
                            Value *op2) -> std::pair<Value *, Value *> {
      Intrinsic::ID intrinsic_id;
      Type *BinOpType = binaryInst->getType();
      bool isUnsigned = false;

      // Heuristic: If instruction has NUW but not NSW then, treat as unsigned
      if (binaryInst->hasNoUnsignedWrap() && !binaryInst->hasNoSignedWrap()) {
        isUnsigned = true;
      }

      switch (binaryInst->getOpcode()) {
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

    auto insertSatOp = [&builder, M](Instruction *binaryInst, Value *op1,
                                     Value *op2) -> Instruction * {
      Intrinsic::ID intrinsic_id;
      Type *BinOpType = binaryInst->getType();
      bool isUnsigned = false;

      if (binaryInst->hasNoUnsignedWrap() && !binaryInst->hasNoSignedWrap()) {
        isUnsigned = true;
      }

      switch (binaryInst->getOpcode()) {
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
      if (binaryInst->getOpcode() == Instruction::Mul) {
        Value *fracBits = ConstantInt::get(BinOpType, 0);
        return builder.CreateCall(satOp, {op1, op2, fracBits});

      } else {
        return builder.CreateCall(satOp, {op1, op2});
      }
    };

    auto [safeResult, isOverflow] = insertSafeOp(binaryInst, op1, op2);
    auto satResult = insertSatOp(binaryInst, op1, op2);

    BasicBlock *checkMapEntryBB = binaryInst->getParent();
    BasicBlock *joinResultBB = checkMapEntryBB->splitBasicBlock(binaryInst);
    BasicBlock *checkOverflowBB = BasicBlock::Create(Ctx, "check.overflow", F);
    BasicBlock *remedOverflowBB =
        BasicBlock::Create(Ctx, "sanitize.overflow", F, joinResultBB);

    checkMapEntryBB->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(checkMapEntryBB);
    createSanitizerGateBranch(builder, F, SanitizerFlag::IntegerOverflow,
                              joinResultBB, checkOverflowBB);

    builder.SetInsertPoint(checkOverflowBB);
    builder.CreateCondBr(isOverflow, remedOverflowBB, joinResultBB);

    builder.SetInsertPoint(remedOverflowBB);
    if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
      builder.CreateCall(fn);
    }
    builder.CreateBr(joinResultBB);

    builder.SetInsertPoint(&*joinResultBB->begin());
    if (strategy == Vulnerability::RemediationStrategies::SAT) {
      binaryInst->replaceAllUsesWith(satResult);
    } else {
      binaryInst->replaceAllUsesWith(safeResult);
    }

    binaryInst->eraseFromParent();
  }
}

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

  for (auto *binaryInst : worklist) {
    Value *isNegative;
    Value *isGreaterThanBitwidth;
    Value *CheckShiftAmtCond;

    BasicBlock *checkMapEntryBB = binaryInst->getParent();
    BasicBlock *joinResultBB = checkMapEntryBB->splitBasicBlock(binaryInst);
    BasicBlock *checkShiftBB = BasicBlock::Create(Ctx, "check.zero", F);
    BasicBlock *preserveShiftBB =
        BasicBlock::Create(Ctx, "safe.shift", F, joinResultBB);
    BasicBlock *remedShiftBB =
        BasicBlock::Create(Ctx, "sanitize.shift", F, joinResultBB);

    checkMapEntryBB->getTerminator()->eraseFromParent();
    builder.SetInsertPoint(checkMapEntryBB);
    createSanitizerGateBranch(builder, F, SanitizerFlag::BitShift,
                              preserveShiftBB, checkShiftBB);

    builder.SetInsertPoint(checkShiftBB);
    Value *shifted_value = binaryInst->getOperand(0);
    Value *bit_pos = binaryInst->getOperand(1);
    unsigned BitWidth = shifted_value->getType()->getIntegerBitWidth();

    isNegative =
        builder.CreateICmpULT(bit_pos, ConstantInt::get(bit_pos->getType(), 0));
    isGreaterThanBitwidth = builder.CreateICmpUGE(
        bit_pos, ConstantInt::get(bit_pos->getType(), BitWidth));
    Value *checkBitPos = builder.CreateOr(isNegative, isGreaterThanBitwidth);
    builder.CreateCondBr(checkBitPos, remedShiftBB, preserveShiftBB);

    builder.SetInsertPoint(remedShiftBB);
    if (Function *fn = getOrCreateRemediationBehavior(M, strategy)) {
      builder.CreateCall(fn);
    }
    Value *safeShift = nullptr;
    Value *safeBitPos;

    switch (binaryInst->getOpcode()) {
    case Instruction::Shl:
      safeBitPos = ConstantInt::get(bit_pos->getType(), 0);
      safeShift = builder.CreateShl(shifted_value, safeBitPos);
      break;

    case Instruction::AShr:
      safeBitPos = ConstantInt::get(bit_pos->getType(), 0);
      safeShift = builder.CreateAShr(shifted_value, safeBitPos);
      break;

    case Instruction::LShr:
      safeBitPos = ConstantInt::get(bit_pos->getType(), 0);
      safeShift = builder.CreateLShr(shifted_value, safeBitPos);
      break;
    }
    builder.CreateBr(joinResultBB);

    builder.SetInsertPoint(preserveShiftBB);
    Value *normalResult = nullptr;

    switch (binaryInst->getOpcode()) {
    case Instruction::Shl:
      normalResult = builder.CreateShl(shifted_value, bit_pos);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::AShr:
      normalResult = builder.CreateAShr(shifted_value, bit_pos);
      builder.CreateBr(joinResultBB);
      break;

    case Instruction::LShr:
      normalResult = builder.CreateLShr(shifted_value, bit_pos);
      builder.CreateBr(joinResultBB);
      break;
    }

    builder.SetInsertPoint(&*joinResultBB->begin());
    PHINode *phi = builder.CreatePHI(binaryInst->getType(), 2);
    phi->addIncoming(safeShift, remedShiftBB);
    phi->addIncoming(normalResult, preserveShiftBB);

    binaryInst->replaceAllUsesWith(phi);
    binaryInst->eraseFromParent();
  }
}
