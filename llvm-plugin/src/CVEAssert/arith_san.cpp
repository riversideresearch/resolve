#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Support/SourceMgr.h"

#include "helpers.hpp"
#include <vector>
#include <optional>

using namespace llvm;

/*
static Instruction *parseInstructionFromString(std::string IR, Function *F) {
    raw_ostream &out = llvm::errs();
    // Wrap string in minimal function
    std::string wrappedIR = 
        "define void @tmp(i32 %0, i32 %1) {\n" +
        IR +
        "\nret void\n}\n";
    
    SMDiagnostic Err;
    F->getContext().setDiscardValueNames(false);
    std::unique_ptr<Module> M = parseAssemblyString(wrappedIR, Err, F->getContext());
    //F->getContext().setDiscardValueNames(true);
    StringRef error_msg = Err.getMessage();

    out << error_msg << "\n";

    // DEBUGGING: Count total number of basic blocks
    Function *miniFunc = M->getFunction("tmp");

    out << "Total basic blocks: " << miniFunc->size();

    BasicBlock &BB = miniFunc->getEntryBlock();

    // Get the first real instruction
    for (Instruction &inst: BB) {
        if (!isa<ReturnInst>(&inst)) {
            return inst.clone();            // clone the instruction to live outside tmp module
        }
    }
    return nullptr;
}
*/
void sanitizeDivideByZero(Function *F) {
    std::vector<Instruction *> worklist;
    IRBuilder<> builder(F->getContext());
    Module *M = F->getParent();
    auto void_ty = Type::getVoidTy(F->getContext());

    FunctionCallee resolve_report_func = getOrCreateResolveReportSantizerTriggered(*M);

    // Loop over each basic block
    for(auto &BB : *F) {
        // Loop over each instruction
        for (auto &instr : BB) {
            // Check if the instruction is a binary operator
            if (auto *BinOp = dyn_cast<BinaryOperator>(&instr)) {
                // Check if the opcode matches sdiv, udiv, fdiv instruction opcode
                if (BinOp->getOpcode() == Instruction::SDiv ||
                    BinOp->getOpcode() == Instruction::UDiv || 
                    BinOp->getOpcode() == Instruction::FDiv ||
                    BinOp->getOpcode() == Instruction::SRem || 
                    BinOp->getOpcode() == Instruction::URem) {
                        // Add to worklist
                        worklist.push_back(BinOp);
                    }
            }
        }
    }

    // Loop over each instruction in the list
    for (auto *binary_inst: worklist) {
        // Set the insertion point at the div instruction
        builder.SetInsertPoint(binary_inst);

        // Extract dividend and divisor
        Value *dividend = binary_inst->getOperand(0);
        Value *divisor = binary_inst->getOperand(1);
        
        // Compare divisor == 0
        Value *IsZero = nullptr;

        // Check opcode of instruction
        if (binary_inst->getOpcode() == Instruction::SDiv ||
            binary_inst->getOpcode() == Instruction::UDiv ||
            binary_inst->getOpcode() == Instruction::SRem ||
            binary_inst->getOpcode() == Instruction::URem
        ) {
                // Insert an integer compare before div
                IsZero = builder.CreateICmpEQ(divisor, ConstantInt::get(divisor->getType(), 0));
                
        } else if (binary_inst->getOpcode() == Instruction::FDiv) {
                // Insert a fp compare
                IsZero = builder.CreateFCmpOEQ(divisor, ConstantFP::get(divisor->getType(), 0.0));
        
        }

        // Split the basic block to insert control flow for div checking.
        BasicBlock *originalBB = binary_inst->getParent();
        BasicBlock *contExecutionBB = originalBB->splitBasicBlock(binary_inst, "do_division");
        BasicBlock *preserveDivBB = BasicBlock::Create(F->getContext(), "preserve_div", F, contExecutionBB);
        BasicBlock *remedDivBB = BasicBlock::Create(F->getContext(), "remed_div", F, contExecutionBB);
        
        // originalBB: Branch if the divisor is zero
        builder.SetInsertPoint(originalBB->getTerminator());
        builder.CreateCondBr(IsZero, remedDivBB, preserveDivBB);
        originalBB->getTerminator()->eraseFromParent();

        // Build remedDivBB: Perform safe division
        builder.SetInsertPoint(remedDivBB);
        builder.CreateCall(resolve_report_func);
        Value *safeDiv = nullptr; 
        
        if (binary_inst->getOpcode() == Instruction::UDiv) {
            Value* safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
            safeDiv = builder.CreateUDiv(dividend, safeIntDivisor);
        } else if (binary_inst->getOpcode() == Instruction::SDiv) {
            // TODO: Consider sign for signed div
            Value* safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
            safeDiv = builder.CreateSDiv(dividend, safeIntDivisor);
        } else if (binary_inst->getOpcode() == Instruction::FDiv) {
            Value* safeFpDivisor = ConstantFP::get(binary_inst->getType(), 1.0);
            safeDiv = builder.CreateFDiv(dividend, safeFpDivisor); 
        
        } else if (binary_inst->getOpcode() == Instruction::URem) {
            Value* safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
            safeDiv = builder.CreateURem(dividend, safeIntDivisor);
        
        } else if (binary_inst->getOpcode() == Instruction::SRem) {
             Value* safeIntDivisor = ConstantInt::get(divisor->getType(), 1);
              safeDiv = builder.CreateSRem(dividend, safeIntDivisor); 
        } 


        builder.CreateBr(contExecutionBB);

        // Build preserveDivBB: Preserve division if case is unaffected
        builder.SetInsertPoint(preserveDivBB);
        Value *normalResult = nullptr;

        if (binary_inst->getOpcode() == Instruction::SDiv) {
            normalResult = builder.CreateSDiv(dividend, divisor);
            builder.CreateBr(contExecutionBB);
        
        } else if (binary_inst->getOpcode() == Instruction::UDiv) {
            normalResult = builder.CreateUDiv(dividend, divisor);
            builder.CreateBr(contExecutionBB);
        
        } else if (binary_inst->getOpcode() == Instruction::FDiv) {
            normalResult = builder.CreateFDiv(dividend, divisor);
            builder.CreateBr(contExecutionBB);
        
        } else if (binary_inst->getOpcode() == Instruction::URem) {
            normalResult = builder.CreateURem(dividend, divisor);
            builder.CreateBr(contExecutionBB);
        
        } else if (binary_inst->getOpcode() == Instruction::SRem) {
            normalResult = builder.CreateSRem(dividend, divisor);
            builder.CreateBr(contExecutionBB);
        }

        // contExecutionBB: Collect results from both control flow branchs using phi
        builder.SetInsertPoint(&*contExecutionBB->begin());
        PHINode *phi_inst = builder.CreatePHI(binary_inst->getType(), 2);
        phi_inst->addIncoming(safeDiv, remedDivBB);
        phi_inst->addIncoming(normalResult, preserveDivBB);

        // Replace uses of original division with phi
        binary_inst->replaceAllUsesWith(phi_inst);

        // Erase old division
        binary_inst->eraseFromParent();
    }
}

Function *replaceUndesirableFunction(Function *F, CallInst *call) {
    LLVMContext &Ctx = F->getContext();
    IRBuilder<> builder(Ctx);

    Function *calledFunc = call->getCalledFunction();
    if (!calledFunc) return nullptr;

    // 1. Create the function name and type.
    std::string sanitizedHandlerName = "resolve_sanitized_function"; 

    if (Function *existing_resolve_sanitize_func = F->getParent()->getFunction(sanitizedHandlerName)) {
        return existing_resolve_sanitize_func;
    }

    FunctionType* sanitizedHandlerType = calledFunc->getFunctionType();

    // Create the function object.
    Function *sanitizedHandlerFunc = Function::Create(sanitizedHandlerType,
        Function::InternalLinkage,
        sanitizedHandlerName,
        F->getParent());
    
    Function *resolve_report_func = getOrCreateResolveReportSantizerTriggered(*F->getParent());
    
    Function::arg_iterator argIter = sanitizedHandlerFunc->arg_begin();
    Value *dividend = argIter++;
    Value *divisor = argIter;

    BasicBlock *EntryBB = BasicBlock::Create(Ctx, "entry", sanitizedHandlerFunc);
    BasicBlock *SanitizedBB = BasicBlock::Create(Ctx, "sanitized_behavior", sanitizedHandlerFunc);
    BasicBlock *ContExeBB = BasicBlock::Create(Ctx, "continue-exe", sanitizedHandlerFunc);

    // EntryBB: contains condition instruction and branch 
    builder.SetInsertPoint(EntryBB);
    
    // Convert the condition into IR
    auto *condition_code = builder.CreateICmpEQ(divisor, ConstantInt::get(divisor->getType(), 0));
    builder.CreateCondBr(condition_code, SanitizedBB, ContExeBB);

    // SanitizedBB: Calls sanitized behavior for arithmetic sanitization
    // Returns dividend 
    builder.SetInsertPoint(SanitizedBB);
    builder.CreateCall(resolve_report_func);
    builder.CreateRet(dividend);

    // ContExec: Makes call to original call instruction and returns that instead.
    builder.SetInsertPoint(ContExeBB);
    Value* safeDiv = builder.CreateCall(calledFunc, { dividend, divisor });
    builder.CreateRet(safeDiv);

    // DEBUGGING
    raw_ostream &out = errs();
    out << *sanitizedHandlerFunc;
    if (verifyFunction(*sanitizedHandlerFunc, &out)) {}

    return sanitizedHandlerFunc;
}

void sanitizeDivideByZeroinFunction(Function *F, std::optional<std::string> funct_name) {
    LLVMContext &Ctx = F->getContext();
    IRBuilder<> builder(Ctx);

    // Container to store call insts
    SmallVector<CallInst *, 4> callsToReplace;

    // loop over each basic block in the vulnerable function
    for (auto &BB: *F) {
        // loop over each instruction 
        for (auto &inst : BB) {
            if (auto *call = dyn_cast<CallInst>(&inst)) {
                Function* calledFunc = call->getCalledFunction();
                if (!calledFunc) { continue; }
                
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
    Function *resolve_sanitized_func = replaceUndesirableFunction(F, callsToReplace.front());

    // Handle calls at each point in module
    for (auto call : callsToReplace) {
        // Set the insertion point befoore call instruction.
        builder.SetInsertPoint(call);
                
        // Recreate argument list
        SmallVector<Value *, 2> func_args;
        for(unsigned i = 0; i < call->arg_size(); ++i) {
            func_args.push_back(call->getOperand(i));
        }

        auto sanitizedCall = builder.CreateCall(resolve_sanitized_func, func_args);

        // replace old uses with new call
        call->replaceAllUsesWith(sanitizedCall);
        call->eraseFromParent();
    }
}

