#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"

#include "helpers.hpp"

using namespace llvm;

static Function *getOrCreateNullPtrLoadSanitizer(Module *M, LLVMContext &Ctx, Type *ty) {
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
    Value *Arbitrary = Constant::getNullValue(ty);
    Builder.CreateRet(Arbitrary);

    // Return Block: returns pointer if non-null
    Builder.SetInsertPoint(LoadBlock);
    Value *ld = Builder.CreateLoad(ty, InputPtr);
    Builder.CreateRet(ld);

    raw_ostream &out = errs();
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {}

    return SanitizeFunc;
}

static Function *getOrCreateNullPtrStoreSanitizer(Module *M, LLVMContext &Ctx, Type *ty) {
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
    //Value *IsNull = Builder.CreateICmpEQ(InputPtr, ConstantPointerNull::get(ptr_ty));
    Value *PtrValue = Builder.CreatePtrToInt(InputPtr, int64_ty);
    Value *IsNull = Builder.CreateICmpULT(PtrValue, ConstantInt::get(int64_ty, 0x1000));
    // Conditional branch
    Builder.CreateCondBr(IsNull, SanitizeBlock, StoreBlock);

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

    // Return Block: returns pointer if non-null
    Builder.SetInsertPoint(StoreBlock);
    Builder.CreateStore(InputVal, InputPtr);
    Builder.CreateRetVoid();

    raw_ostream &out = errs();
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {}

    return SanitizeFunc;
}

void sanitizeNullPointers(Function *f) {
    IRBuilder<> builder(f->getContext());

    std::vector<LoadInst*> loadList;
    std::vector<StoreInst*> storeList;
    
    for (auto &BB : *f) {
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

        auto loadFn = getOrCreateNullPtrLoadSanitizer(f->getParent(), f->getContext(), valueTy);

        auto sanitized_load = builder.CreateCall(loadFn, {Inst->getPointerOperand()});
        Inst->replaceAllUsesWith(sanitized_load);
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

        auto storeFn = getOrCreateNullPtrStoreSanitizer(f->getParent(), f->getContext(), valueTy);

        auto sanitized_load = builder.CreateCall(storeFn, {Inst->getPointerOperand(), Inst->getValueOperand()});
        Inst->removeFromParent();
        Inst->deleteValue();
    }
}

