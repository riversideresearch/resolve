#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <utility>
#include <vector>

using namespace llvm;

struct ObjHook : public PassInfoMixin<ObjHook> {
public:
  Function *getOrCreateResolveMalloc(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto void_ty = Type::getVoidTy(Ctx);

    FunctionType *resolveMallocFuncTy =
        FunctionType::get(ptr_ty, {Type::getInt64Ty(Ctx)}, false);

    if (Function *F = M.getFunction("resolve_malloc"))
      if (!F->isDeclaration())
        return F;

    Function *resolveMallocFunc = Function::Create(
        resolveMallocFuncTy, GlobalValue::WeakAnyLinkage, "resolve_malloc", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveMallocFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeMalloc = M.getOrInsertFunction(
        "malloc", FunctionType::get(ptr_ty, {Type::getInt64Ty(Ctx)}, false));
    auto arg = resolveMallocFunc->arg_begin();
    Value *sizeArg = &*arg;

    CallInst *callRealMalloc = builder.CreateCall(runtimeMalloc, {sizeArg});
    callRealMalloc->setTailCall(false);

    builder.CreateRet(callRealMalloc);
    return resolveMallocFunc;
  }

  Function *getOrCreateResolveFree(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto void_ty = Type::getVoidTy(Ctx);

    FunctionType *resolveFreeFuncTy =
        FunctionType::get(void_ty, {ptr_ty}, false);

    if (Function *F = M.getFunction("resolve_free"))
      if (!F->isDeclaration())
        return F;

    Function *resolveFreeFunc = Function::Create(
        resolveFreeFuncTy, GlobalValue::WeakAnyLinkage, "resolve_free", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveFreeFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeFree = M.getOrInsertFunction(
        "free", FunctionType::get(void_ty, {ptr_ty}, false));

    auto arg = resolveFreeFunc->arg_begin();
    Value *ptrArg = &*arg;
    builder.CreateCall(runtimeFree, {ptrArg});
    builder.CreateRetVoid();
    return resolveFreeFunc;
  }

  Function *getOrCreateResolveCalloc(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto i64_ty = Type::getInt64Ty(Ctx);

    FunctionType *resolveCallocFuncTy =
        FunctionType::get(ptr_ty, {i64_ty, i64_ty}, false);

    if (Function *F = M.getFunction("resolve_calloc"))
      if (!F->isDeclaration())
        return F;

    Function *resolveCallocFunc = Function::Create(
        resolveCallocFuncTy, GlobalValue::WeakAnyLinkage, "resolve_calloc", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveCallocFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeCalloc = M.getOrInsertFunction(
        "calloc", FunctionType::get(ptr_ty, {i64_ty, i64_ty}, false));

    auto arg = resolveCallocFunc->arg_begin();
    Value *numElems = &*arg++;
    Value *sizeElems = &*arg;

    Value *realCalloc =
        builder.CreateCall(runtimeCalloc, {numElems, sizeElems});
    builder.CreateRet(realCalloc);
    return resolveCallocFunc;
  }

  Function *getOrCreateResolveRealloc(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto i64_ty = Type::getInt64Ty(Ctx);

    FunctionType *resolveReallocFuncTy =
        FunctionType::get(ptr_ty, {ptr_ty, i64_ty}, false);

    if (Function *F = M.getFunction("resolve_realloc"))
      return F;

    Function *resolveReallocFunc =
        Function::Create(resolveReallocFuncTy, GlobalValue::WeakAnyLinkage,
                         "resolve_realloc", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveReallocFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeRealloc = M.getOrInsertFunction(
        "realloc", FunctionType::get(ptr_ty, {ptr_ty, i64_ty}, false));

    auto argIter = resolveReallocFunc->arg_begin();
    Value *ptrArg = &*argIter++;
    Value *sizeElems = &*argIter;

    Value *realRealloc =
        builder.CreateCall(runtimeRealloc, {ptrArg, sizeElems});
    builder.CreateRet(realRealloc);
    return resolveReallocFunc;
  }

  Function *getOrCreateResolveStrdup(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);

    FunctionType *resolveStrdupFuncTy =
        FunctionType::get(ptr_ty, {ptr_ty}, false);

    if (Function *F = M.getFunction("resolve_strdup"))
      if (!F->isDeclaration())
        return F;

    Function *resolveStrdupFunc = Function::Create(
        resolveStrdupFuncTy, GlobalValue::WeakAnyLinkage, "resolve_strdup", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveStrdupFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeStrdup = M.getOrInsertFunction(
        "strdup", FunctionType::get(ptr_ty, {ptr_ty}, false));

    auto argIter = resolveStrdupFunc->arg_begin();

    Value *ptrArg = &*argIter;
    Value *realStrdup = builder.CreateCall(runtimeStrdup, {ptrArg});
    builder.CreateRet(realStrdup);
    return resolveStrdupFunc;
  }

  Function *getOrCreateResolveStrndup(Module &M) {
    auto &Ctx = M.getContext();
    auto ptr_ty = PointerType::get(Ctx, 0);
    auto i64_ty = Type::getInt64Ty(Ctx);

    FunctionType *resolveStrndupFuncTy =
        FunctionType::get(ptr_ty, {ptr_ty, i64_ty}, false);

    if (Function *F = M.getFunction("resolve_strndup"))
      if (!F->isDeclaration())
        return F;

    Function *resolveStrndupFunc =
        Function::Create(resolveStrndupFuncTy, GlobalValue::WeakAnyLinkage,
                         "resolve_strndup", M);

    BasicBlock *BB = BasicBlock::Create(Ctx, "entry", resolveStrndupFunc);
    IRBuilder<> builder(BB);

    FunctionCallee runtimeStrndup = M.getOrInsertFunction(
        "strndup", FunctionType::get(ptr_ty, {ptr_ty, i64_ty}, false));

    auto argIter = resolveStrndupFunc->arg_begin();
    Value *ptrArg = &*argIter++;
    Value *sizeElems = &*argIter;

    Value *realStrndup =
        builder.CreateCall(runtimeStrndup, {ptrArg, sizeElems});
    builder.CreateRet(realStrndup);
    return resolveStrndupFunc;
  }

  void runOnFunction(Function &F, Module &M, LLVMContext &Ctx) {
    std::vector<CallInst *> mallocCalls;
    std::vector<CallInst *> callocCalls;
    std::vector<CallInst *> reallocCalls;
    std::vector<CallInst *> strdupCalls;
    std::vector<CallInst *> strndupCalls;
    std::vector<CallInst *> freeCalls;

    Function *resolvemallocFunc = getOrCreateResolveMalloc(M);
    Function *resolvecallocFunc = getOrCreateResolveCalloc(M);
    Function *resolvereallocFunc = getOrCreateResolveRealloc(M);
    Function *resolvefreeFunc = getOrCreateResolveFree(M);
    Function *resolvestrdupFunc = getOrCreateResolveStrdup(M);
    Function *resolvestrndupFunc = getOrCreateResolveStrndup(M);

    // FunctionCallee resolvemallocFunc = M.getOrInsertFunction(
    // "resolve_malloc",
    // FunctionType::get(PointerType::get(Ctx, 0), { Type::getInt64Ty(Ctx)},
    // false ));

    // FunctionCallee resolvecallocFunc = M.getOrInsertFunction(
    // "resolve_calloc",
    // FunctionType::get(PointerType::get(Ctx, 0), { Type::getInt64Ty(Ctx),
    // Type::getInt64Ty(Ctx)}, false ));

    // FunctionCallee resolvereallocFunc = M.getOrInsertFunction(
    // "resolve_realloc",
    // FunctionType::get(PointerType::get(Ctx, 0), { PointerType::get(Ctx, 0),
    // Type::getInt64Ty(Ctx)}, false));

    // FunctionCallee resolvestrdupFunc = M.getOrInsertFunction(
    // "resolve_strdup",
    // FunctionType::get(PointerType::get(Ctx, 0), { PointerType::get(Ctx, 0)},
    // false));

    // FunctionCallee resolvestrndupFunc = M.getOrInsertFunction(
    // "resolve_strndup",
    // FunctionType::get(PointerType::get(Ctx, 0), { PointerType::get(Ctx, 0),
    // Type::getInt64Ty(Ctx)}, false));

    // FunctionCallee resolvefreeFunc = M.getOrInsertFunction(
    // "resolve_free",
    // FunctionType::get(Type::getVoidTy(Ctx), { PointerType::get(Ctx, 0)},
    // false ));

    for (auto &BB : F) {
      for (auto &inst : BB) {
        if (auto *call = dyn_cast<CallInst>(&inst)) {
          Function *calledFunc = call->getCalledFunction();
          if (!calledFunc)
            continue;

          StringRef funcName = calledFunc->getName();

          if (funcName == "malloc") {
            mallocCalls.push_back(call);
          } else if (funcName == "free") {
            freeCalls.push_back(call);
          } else if (funcName == "calloc") {
            callocCalls.push_back(call);
          } else if (funcName == "realloc") {
            reallocCalls.push_back(call);
          } else if (funcName == "strdup") {
            strdupCalls.push_back(call);
          } else if (funcName == "strndup") {
            strndupCalls.push_back(call);
          }
        }
      }
    }

    for (auto *mallocCall : mallocCalls) {
      IRBuilder<> builder(mallocCall);

      Value *size_arg = mallocCall->getArgOperand(0);
      size_arg = builder.CreateZExtOrBitCast(size_arg, Type::getInt64Ty(Ctx));

      CallInst *resolve_malloc_call =
          builder.CreateCall(resolvemallocFunc, {size_arg});

      mallocCall->replaceAllUsesWith(resolve_malloc_call);
      mallocCall->eraseFromParent();
    }

    for (auto *freeCall : freeCalls) {
      IRBuilder<> builder(freeCall);

      Value *ptr_arg = freeCall->getArgOperand(0);
      CallInst *resolve_free_call =
          builder.CreateCall(resolvefreeFunc, {ptr_arg});
      // freeCall->replaceAllUsesWith(resolve_free_call);
      freeCall->eraseFromParent();
    }

    for (auto *callocCall : callocCalls) {
      IRBuilder<> builder(callocCall);

      // nelems and sizeelems
      Value *num_elems = callocCall->getOperand(0);
      Value *size_elems = callocCall->getOperand(1);

      CallInst *resolve_calloc_call =
          builder.CreateCall(resolvecallocFunc, {num_elems, size_elems});
      callocCall->replaceAllUsesWith(resolve_calloc_call);
      callocCall->eraseFromParent();
    }

    for (auto *reallocCall : reallocCalls) {
      IRBuilder<> builder(reallocCall);

      // ptr and size of elements
      Value *ptr_arg = reallocCall->getOperand(0);
      Value *size_elems = reallocCall->getOperand(1);

      CallInst *resolve_realloc_call =
          builder.CreateCall(resolvereallocFunc, {ptr_arg, size_elems});
      reallocCall->replaceAllUsesWith(resolve_realloc_call);
      reallocCall->eraseFromParent();
    }

    for (auto *strdupCall : strdupCalls) {
      IRBuilder<> builder(strdupCall);

      Value *ptr_arg = strdupCall->getOperand(0);
      CallInst *resolve_strdup_call =
          builder.CreateCall(resolvestrdupFunc, {ptr_arg});
      strdupCall->replaceAllUsesWith(resolve_strdup_call);
      strdupCall->eraseFromParent();
    }

    for (auto *strndupCall : strndupCalls) {
      IRBuilder<> builder(strndupCall);

      Value *ptr_arg = strndupCall->getOperand(0);
      Value *size_arg = strndupCall->getOperand(1);

      CallInst *resolve_strndup_call =
          builder.CreateCall(resolvestrndupFunc, {ptr_arg, size_arg});
      strndupCall->replaceAllUsesWith(resolve_strndup_call);
      strndupCall->eraseFromParent();
    }
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();
    for (auto &F : M) {
      if (F.isDeclaration())
        continue;

      StringRef func_name = F.getName();
      if (func_name.starts_with("resolve_"))
        continue;

      runOnFunction(F, M, Ctx);
    }
    /* IR is modified */
    return PreservedAnalyses::none();
  }
};

/* New PM Registration */
PassPluginLibraryInfo getObjHookPassInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ObjHook", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(ObjHook());
                  return true;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getObjHookPassInfo();
}
