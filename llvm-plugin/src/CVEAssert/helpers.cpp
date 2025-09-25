
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include "CVEAssert.hpp"
#include "helpers.hpp"

using namespace llvm;

Function *getOrCreateIsHeap(Module *M, LLVMContext &Ctx) {
    std::string handlerName = "resolve_is_heap";

    if (auto handler = M->getFunction(handlerName))
    return handler;

    IRBuilder<> Builder(Ctx);
    // TODO: handle address spaces other than 0
    auto ptr_ty = PointerType::get(Ctx, 0);

    // TODO: write this in asm as some kind of sanitzer_rt?
    FunctionType *FuncType = FunctionType::get(Type::getIntNTy(Ctx, 1), {ptr_ty}, false);
    Function *SanitizeFunc = Function::Create(FuncType, Function::InternalLinkage, handlerName, M);

    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", SanitizeFunc);
    Builder.SetInsertPoint(Entry);

    // Get function argument
    Argument *InputPtr = SanitizeFunc->getArg(0);

    FunctionType *AsmType = FunctionType::get(ptr_ty, {});
    auto read_sp_asm = InlineAsm::get(AsmType, "mov %rsp, $0", "=r,~{dirflag},~{fpsr},~{flags}", true);
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
    out << *SanitizeFunc;
    if (verifyFunction(*SanitizeFunc, &out)) {}

    return SanitizeFunc;
}

Function *getOrCreateResolveReportSantizerTriggered(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto void_ty = Type::getVoidTy(Ctx);

    FunctionType *resolve_report_func_ty = FunctionType::get(void_ty, {}, false);
    if (Function *F = M.getFunction("resolve_report_sanitizer_triggered"))
        if (!F->isDeclaration()) 
            return F;

    Function* resolve_report_func = Function::Create(
        resolve_report_func_ty,
        // FIXME: libresolve right now overrides this function and breaks exit strategy
        // Find a way to make libresolve respect CVE_ASSERT_STRATEGY and then make this weak again
        (strcmp(CVE_ASSERT_STRATEGY, "EXIT") == 0) ? GlobalValue::InternalLinkage : GlobalValue::WeakAnyLinkage,
        "resolve_report_sanitizer_triggered",
        M
    );

    BasicBlock *BB = BasicBlock::Create(Ctx, "", resolve_report_func);
    IRBuilder<> builder(BB);

    if(strcmp(CVE_ASSERT_STRATEGY, "EXIT") == 0) {
        llvm::Function* exitFn = M.getFunction("exit");
        llvm::Value *exitCode = builder.getInt32(3);
        if(exitFn) {
            builder.CreateCall(exitFn, {exitCode});
        }
        else {
            raw_ostream &out = errs();
            out << "[CVEAssert] Could not resolve libc function \"exit\" \n";
        }
    }

    builder.CreateRetVoid();

    raw_ostream &out = errs();
    out << *resolve_report_func;
    if (verifyFunction(*resolve_report_func, &out)) {}

    return resolve_report_func;
}
