/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include "Vulnerability.hpp"
#include "helpers.hpp"

using namespace llvm;

static Function *getOrCreateNullPtrLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy, Value *jmpBufPtr = nullptr) {
    Twine handlerName = "resolve_sanitize_null_ptr_ld_" + getLLVMType(ty);
    SmallVector<char> handlerNameStr;

    if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
        return handler;

    IRBuilder<> Builder(Ctx);
    // TODO: handle address spaces other than 0
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto int64_ty = Type::getInt64Ty(Ctx);
    auto void_ty = Type::getVoidTy(Ctx);

    // TODO: write this in asm as some kind of sanitzer_rt?
    FunctionType *FuncType = FunctionType::get(ty, {ptr_ty}, false);
    Function *SanitizeFunc = Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeFunc);
    BasicBlock *SanitizeBlock = BasicBlock::Create(Ctx, "sanitize_block", SanitizeFunc);
    BasicBlock *LoadBlock = BasicBlock::Create(Ctx, "load_block", SanitizeFunc);

    // Set insertion point to entry block
    Builder.SetInsertPoint(Entry);
    
    // Get function argument
    Argument *InputPtr = SanitizeFunc->getArg(0);

    // Compare pointer with null (opaque ptrs use generic ptr type)
    // TODO: Sanitize other invalid pointers
    Value *PtrValue = Builder.CreatePtrToInt(InputPtr, int64_ty);
    Value *IsNull = Builder.CreateICmpULT(PtrValue, ConstantInt::get(int64_ty, 0x1000));

    // Conditional branch
    Builder.CreateCondBr(IsNull, SanitizeBlock, LoadBlock);

    // Trap Block: calls libmemorizer_trap
    Builder.SetInsertPoint(SanitizeBlock);
    FunctionType* LogMemInstFuncTy = FunctionType::get(
        void_ty,
        { ptr_ty },
        false
    );
    FunctionCallee LogMemInstFunc = M->getOrInsertFunction("resolve_report_sanitize_mem_inst_triggered", LogMemInstFuncTy);
    Builder.CreateCall(LogMemInstFunc, { InputPtr });
    Builder.CreateRetVoid();

    switch(strategy) {
        case Vulnerability::RemediationStrategies::EXIT:
            Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
            Builder.CreateUnreachable();
            break;

        // TODO: Add support for recover remediation strategy.
        case Vulnerability::RemediationStrategies::RECOVER:
            FunctionCallee longjmpFn = M->getOrInsertFunction(
                "longjmp", FunctionType::get(void_ty, { ptr_ty }, false)
            );

            Value *longjmpVal = ConstantInt::get(Type::getInt32Ty(Ctx), 42);
            Builder.CreateCall(longjmpFn, { jmpBufPtr, longjmpVal });
            Builder.CreateUnreachable();
            break;

        
        case Vulnerability::RemediationStrategies::SAFE:
            Builder.CreateRet(Constant::getNullValue(ty));
            break;
    }
    

    // Return Block: returns pointer if non-null
    Builder.SetInsertPoint(LoadBlock);
    Value *ld = Builder.CreateLoad(ty, InputPtr);
    Builder.CreateRet(ld);

    raw_ostream &out = errs();
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {}

    return SanitizeFunc;
}

static Function *getOrCreateNullPtrStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty, Vulnerability::RemediationStrategies strategy, Value *jmpBufPtr = nullptr) {
    Twine handlerName = "resolve_sanitize_null_ptr_st_" + getLLVMType(ty);
    SmallVector<char> handlerNameStr;

    if (auto handler = M->getFunction(handlerName.toStringRef(handlerNameStr)))
        return handler;

    IRBuilder<> Builder(Ctx);
    // TODO: handle address spaces other than 0
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto int64_ty = Type::getInt64Ty(Ctx);
    auto void_ty = Type::getVoidTy(Ctx);

    // TODO: write this in asm as some kind of sanitzer_rt?
    FunctionType *FuncType = FunctionType::get(Type::getVoidTy(Ctx), {ptr_ty, ty}, false);
    Function *SanitizeFunc = Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeFunc);
    BasicBlock *SanitizeBlock = BasicBlock::Create(Ctx, "sanitize_block", SanitizeFunc);
    BasicBlock *StoreBlock = BasicBlock::Create(Ctx, "store_block", SanitizeFunc);

    // Set insertion point to entry block
    Builder.SetInsertPoint(Entry);
    
    // Get function argument
    Argument *InputPtr = SanitizeFunc->getArg(0);
    Argument *InputVal = SanitizeFunc->getArg(1);

    // Compare pointer with null (opaque ptrs use generic ptr type)
    // TODO: Sanitize other invalid pointers
    // Updating conditional check for ptr value less than 0x1000
    // Unix systems do not map first page of memory, 
    // we need to detect remdiate pointers within this range. 
    Value *PtrValue = Builder.CreatePtrToInt(InputPtr, int64_ty);
    Value *IsNull = Builder.CreateICmpULT(PtrValue, ConstantInt::get(int64_ty, 0x1000));
    Builder.CreateCondBr(IsNull, SanitizeBlock, StoreBlock);

    // Trap Block: calls libresolve_trap
    Builder.SetInsertPoint(SanitizeBlock);
    FunctionType* LogMemInstFuncTy = FunctionType::get(
        void_ty,
        { ptr_ty },
        false
    );
    FunctionCallee LogMemInstFunc = M->getOrInsertFunction("resolve_report_sanitize_mem_inst_triggered", LogMemInstFuncTy);
    Builder.CreateCall(LogMemInstFunc, { InputPtr });
    
    // TODO: Add support for recovery remediation strategy 
    switch(strategy) {
        case Vulnerability::RemediationStrategies::EXIT:
            Builder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
            Builder.CreateUnreachable();
            break;
        
        case Vulnerability::RemediationStrategies::RECOVER:
            FunctionCallee longjmpFn = M->getOrInsertFunction(
                "longjmp", FunctionType::get(void_ty, { ptr_ty }, false)
            );

            Value *longjmpVal = ConstantInt::get(Type::getInt32Ty(Ctx), 42);
            Builder.CreateCall(longjmpFn, { jmpBufPtr, longjmpVal });
            Builder.CreateUnreachable();
            break;
    }

    // Return Block: returns pointer if non-null
    Builder.SetInsertPoint(StoreBlock);
    Builder.CreateStore(InputVal, InputPtr);
    Builder.CreateRetVoid();

    raw_ostream &out = errs();
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {}

    return SanitizeFunc;
}

void sanitizeNullPointers(Function *F, Vulnerability::RemediationStrategies strategy) {
    IRBuilder<> builder(F->getContext());

    std::vector<LoadInst*> loadList;
    std::vector<StoreInst*> storeList;

    switch(strategy) {
        case Vulnerability::RemediationStrategies::EXIT:
            break;
        case Vulnerability::RemediationStrategies::RECOVER:
            sanitizeNullPointersRecover(F, strategy);
            return;
        
        default:
            llvm::errs() << "[CVEAssert] Error: sanitizeNullPointers does not support remediation strategy "
                         << "defaulting to EXIT strategy!\n";
            strategy = Vulnerability::RemediationStrategies::EXIT;
            break;
    }
    
    for (auto &BB : *F) {
        for (auto &I : BB) {
            if (auto Inst = dyn_cast<LoadInst>(&I)) {
                loadList.push_back(Inst);
            } else if (auto Inst = dyn_cast<StoreInst>(&I)) {
                storeList.push_back(Inst);
            }
        }
    }

    for (auto Inst : loadList) {
        builder.SetInsertPoint(Inst);
        auto valueTy = Inst->getType();
        if (getLLVMType(valueTy) == "") {
            errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy << "\n";
            continue;
        }

        auto loadFn = getOrCreateNullPtrLoadSanitizer(F->getParent(), F->getContext(), valueTy, strategy);

        auto sanitizedloadFn = builder.CreateCall(loadFn, {Inst->getPointerOperand()});
        Inst->replaceAllUsesWith(sanitizedloadFn);
        Inst->removeFromParent();
        Inst->deleteValue();
    }
        
    for (auto Inst : storeList) {
        builder.SetInsertPoint(Inst);
        auto valueTy = Inst->getValueOperand()->getType();
        if (getLLVMType(valueTy) == "") {
            errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy << "\n";
            continue;
        }

        auto storeFn = getOrCreateNullPtrStoreSanitizer(F->getParent(), F->getContext(), valueTy, strategy);

        auto sanitizedstoreFn = builder.CreateCall(storeFn, {Inst->getPointerOperand(), Inst->getValueOperand()});
        Inst->replaceAllUsesWith(sanitizedstoreFn);
        Inst->removeFromParent();
        Inst->deleteValue();
    }
}

void sanitizeNullPointersRecover(Function *F, Vulnerability::RemediationStrategies strategy) {
    Module *M = F->getParent();
    auto &Ctx = M->getContext();
    IRBuilder<> builder(Ctx);

    std::vector<LoadInst*> loadList;
    std::vector<StoreInst*> storeList;

    auto void_ty = Type::getVoidTy(Ctx);
    auto ptr_ty  = PointerType::get(Ctx, 0);
    auto i32_ty = Type::getInt32Ty(Ctx);

    FunctionCallee setjmpFn = M->getOrInsertFunction(
        "setjmp",
        FunctionType::get(i32_ty, { ptr_ty }, false)
    );

    FunctionCallee longjmpFn = M->getOrInsertFunction(
        "longjmp",
        FunctionType::get(void_ty, { ptr_ty }, false)
    );

    // Insert jmp_buf
    BasicBlock &entry = F->getEntryBlock(); 
    BasicBlock *sjljEntry = BasicBlock::Create(Ctx, "", F, &entry);
    IRBuilder<> sjBuilder(sjljEntry);

    ArrayType *jmpBufArrTy = ArrayType::get(Type::getInt8Ty(Ctx), 200);
    AllocaInst * jmpBufAlloca = sjBuilder.CreateAlloca(jmpBufArrTy, nullptr, "jmpbuf");
    /* NOTE: I am not sure if the alloca instruction automatically returns an opaque pointer 
            when I read the documentation it says 'alloca' returns a pointer of the appropriate 
            type. I am not sure if the alloca automatically retun 
    */
   /* TODO: If this breaks during compilation fix it */
    Value *setjmpVal = sjBuilder.CreateCall(setjmpFn, { jmpBufAlloca });
    Value *isInitial = sjBuilder.CreateICmpEQ(setjmpVal, ConstantInt::get(i32_ty, 0));

    // recoverBB: calls error handling function when setjmp returns non-zero
    BasicBlock *recoverBB = BasicBlock::Create(Ctx, "", F);
    sjBuilder.CreateCondBr(isInitial, &entry, recoverBB);

    IRBuilder<> recoverBuilder(recoverBB);
    recoverBuilder.CreateCall(getOrCreateRemediationBehavior(M, strategy));
    recoverBuilder.CreateUnreachable();

    for (auto& BB : *F) {
        for (auto &I: BB) {
            if (auto Inst = dyn_cast<LoadInst>(&I)) {
                loadList.push_back(Inst);
            } else if (auto Inst = dyn_cast<StoreInst>(&I)) {
                storeList.push_back(Inst);
            }
        }
    }

    for (auto Inst: loadList) {
        builder.SetInsertPoint(Inst);
        auto valueTy = Inst->getType();
        if (getLLVMType(valueTy) == "") {
            errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy << "\n";
            continue;
        }

        auto loadFn = getOrCreateNullPtrLoadSanitizer(F->getParent(), F->getContext(), valueTy, strategy, jmpBufAlloca);
        
        auto sanitizedloadFn = builder.CreateCall(loadFn, { Inst->getPointerOperand() });
        Inst->replaceAllUsesWith(sanitizedloadFn);
        Inst->removeFromParent();
        Inst->deleteValue();
    }

    for (auto Inst: storeList) {
        builder.SetInsertPoint(Inst);
        auto valueTy = Inst->getType();
        if (getLLVMType(valueTy) == "") {
            errs() << "[CVEAssert] Warning: skipping unsupported type " << *valueTy << "\n";
            continue;
        }

        auto storeFn = getOrCreatePtrStoreSanitizer(F->getParent(), F->getContext(), valueTy, strategy, jmpBufAlloca);
        auto sanitizedstoreFn = builder.CreateCall(storeFn, { Inst->getPointerOperand(), Inst->getValueOperand() });
        Inst->replaceAllUsesWith(sanitizedstoreFn);
        Inst->removeFromParent();
        Inst->deleteValue();
    }
}