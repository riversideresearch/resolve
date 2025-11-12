/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/Transforms/Instrumentation.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

using namespace llvm;

/* Static hashmap to store the function names and their globalstringptr value */
static std::map<Function *, Value *> FuncNames;

/* Helper function to get the argument type as a string */
std::string getLLVMType(Type *ty) {
  if (ty->isIntegerTy(8))
    return "i8";
  if (ty->isIntegerTy(16))
    return "i16";
  if (ty->isIntegerTy(16))
    return "i16";
  if (ty->isIntegerTy(16))
    return "i16";
  if (ty->isIntegerTy(32))
    return "i32";
  if (ty->isIntegerTy(64))
    return "i64";
  if (ty->isFloatingPointTy())
    return "float";
  if (ty->isPointerTy())
    return "ptr";
  if (ty->isVoidTy())
    return "void";

  report_fatal_error("unsupported type");
}

struct AnnotateFunctions : public PassInfoMixin<AnnotateFunctions> {

  void getGlobalFunctionName(Module &M, Function &F, LLVMContext &ctx) {
    Value *&FnNameGlobal = FuncNames[&F];

    if (!FnNameGlobal) {
      std::string GlobalName = "resolve_fn_" + F.getName().str();
      Constant *funcNameConst =
          ConstantDataArray::getString(ctx, F.getName(), true);
      GlobalVariable *GV = new GlobalVariable(M, funcNameConst->getType(), true,
                                              GlobalValue::InternalLinkage,
                                              funcNameConst, GlobalName);

      GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      GV->setAlignment(Align());
      FnNameGlobal = ConstantExpr::getPointerCast(GV, PointerType::get(ctx, 0));
    }
  }

  void emitFuncArg(Function *F, Value *arg, Instruction *insertion_before) {
    Module *M = F->getParent();
    LLVMContext &ctx = M->getContext();
    Type *arg_type = arg->getType();
    IRBuilder<> builder(insertion_before);

    std::string argument_str = "libresolve_arg_" + getLLVMType(arg_type);

    FunctionType *argFnTy = FunctionType::get(
        Type::getVoidTy(ctx), {arg_type, PointerType::get(ctx, 0)}, false);

    FunctionCallee resolve_arg_callee =
        M->getOrInsertFunction(argument_str, argFnTy);
    builder.CreateCall(resolve_arg_callee, {arg, FuncNames[F]});
  }

  void emitFuncRetValue(Function *F, Value *retval,
                        Instruction *insert_before) {

    Module *M = F->getParent();
    LLVMContext &ctx = M->getContext();
    std::string resolve_ret = "libresolve_ret_";
    IRBuilder<> builder(insert_before);

    if (!retval) {
      resolve_ret += "void";
      FunctionType *ResolveVoidFuncTy = FunctionType::get(
          Type::getVoidTy(ctx), {PointerType::get(ctx, 0)}, false);

      FunctionCallee resolve_ret_callee =
          M->getOrInsertFunction(resolve_ret, ResolveVoidFuncTy);
      builder.CreateCall(resolve_ret_callee, {FuncNames[F]});

    } else {
      resolve_ret += getLLVMType(retval->getType());
      FunctionType *ResolveVoidFuncTy = FunctionType::get(
          Type::getVoidTy(ctx), {retval->getType(), PointerType::get(ctx, 0)},
          false);

      FunctionCallee resolve_ret_callee =
          M->getOrInsertFunction(resolve_ret, ResolveVoidFuncTy);
      builder.CreateCall(resolve_ret_callee, {retval, FuncNames[F]});
    }
  }

  void enumBasicBlock(Function *F, int64_t counter,
                      Instruction *insert_before) {
    Module *M = F->getParent();
    LLVMContext &ctx = M->getContext();
    ConstantInt *BB_count =
        ConstantInt::get(IntegerType::get(ctx, 64), counter);
    std::string resolve_bb_str = "libresolve_bb";
    IRBuilder<> builder(insert_before);

    FunctionType *BBCountFnType = FunctionType::get(
        Type::getVoidTy(ctx),
        {IntegerType::get(ctx, 64), PointerType::get(ctx, 0)}, false);

    FunctionCallee resolve_bb_callee =
        M->getOrInsertFunction(resolve_bb_str, BBCountFnType);
    builder.CreateCall(resolve_bb_callee, {BB_count, FuncNames[F]});
  }

  void runOnFunction(Module &M, Function &F) {
    LLVMContext &ctx = M.getContext();

    if (F.isDeclaration() || F.isIntrinsic())
      return;

    getGlobalFunctionName(M, F, ctx);

    BasicBlock &entry = F.getEntryBlock();
    auto InsertionIter = entry.getFirstInsertionPt();
    if (InsertionIter == entry.end()) {
      report_fatal_error("[ERROR]: Could not find insertion point in function");
    }

    Instruction *insertBefore = &*InsertionIter;

    for (Argument &arg : F.args()) {
      emitFuncArg(&F, &arg, insertBefore);
    }

    int64_t bb_counter = 0;
    for (auto &BB : F) {
      Instruction *insertion_pt;

      auto bb_it = BB.getFirstInsertionPt();
      if (bb_it == BB.end()) {
        continue;
      }

      insertion_pt = &*bb_it;
      enumBasicBlock(&F, bb_counter++, insertion_pt);
    }

    for (auto &BB : F) {
      for (auto &inst : BB) {
        if (auto *retInst = dyn_cast<ReturnInst>(&inst)) {
          Value *retVal =
              retInst->getNumOperands() == 1 ? retInst->getOperand(0) : nullptr;
          emitFuncRetValue(&F, retVal, retInst);
        }
      }
    }
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {

    for (auto &F : M) {
      runOnFunction(M, F);
    }

    return PreservedAnalyses::none();
  }
};

// void getFunctionNameGlobal(Module& M, Function& F, LLVMContext& ctx) {
//     /* Look up function name in hashmap */
//     Value *&FnNameGlobal = FuncNames[&F];
//     if(!FnNameGlobal) {
//         std::string GlobalName = "resolve_fn_" + F.getName().str();
//         Constant *strConstant = ConstantDataArray::getString(ctx,
//         F.getName(), true); GlobalVariable *GV = new GlobalVariable(
//                 M,
//                 strConstant->getType(),
//                 true,
//                 GlobalValue::PrivateLinkage,
//                 strConstant,
//             GlobalName);
//         GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
//         GV->setAlignment(Align(1));
//         FnNameGlobal = ConstantExpr::getPointerCast(GV, PointerType::get(ctx,
//         0));
//     }
// }

// void emitLavaArg(Value* v, IRBuilder<> &B, Module& M, LLVMContext& ctx,
// Function* F) {
//     /* Function builds the libresolve_arg_ function call with the llvm type
//     of the argument */

//     /* Get the type of the argument */
//     Type* lava_arg_type = v->getType();

//     /* Concatenate "libresolve_arg_" prefix with llvm type of the argument */
//     std::string lava_arg_str = "libresolve_arg_" +
//     getLLVMType(lava_arg_type);

//     /* Declare function type with arg type and pointer type function name */
//     FunctionType *argFnTy = FunctionType::get(
//         Type::getVoidTy(ctx),
//         { lava_arg_type, PointerType::get(ctx, 0) },
//         false
//     );

//     /* Build the llvm function call instruction */
//     FunctionCallee lava_arg_callee = M.getOrInsertFunction(lava_arg_str,
//     argFnTy);

//     /* Insert the call */
//     B.CreateCall(lava_arg_callee, { v, FuncNames[F] });

// }

// void emitLavaRetVal(Value* v, IRBuilder<> &B, Module& M, LLVMContext& ctx,
// Function* F) {
//     /* Function build libresolve_ret_ function call with the llvm type */

//     if (!v) { /* Handles void case */
//         std::string lava_ret_str = "libresolve_ret_void";
//         FunctionType* voidRetFnTy = FunctionType::get(
//                 Type::getVoidTy(ctx),
//                 { PointerType::get(ctx, 0) },
//                 false
//         );
//         FunctionCallee lava_ret_callee = M.getOrInsertFunction(lava_ret_str,
//         voidRetFnTy); B.CreateCall(lava_ret_callee, { FuncNames[F] });

//     } else { /* Handles non-void case */
//         Type* lava_ret_type = v->getType();
//         std::string lava_ret_str = "libresolve_ret_" +
//         getLLVMType(lava_ret_type);

//         /* Declare function type with arg type and pointer type for function
//         name */ FunctionType *retFnTy = FunctionType::get(
//             Type::getVoidTy(ctx),
//             { lava_ret_type, PointerType::get(ctx, 0) },
//             false
//         );

//         /* Build the llvm function call instruction */
//         FunctionCallee lava_arg_callee = M.getOrInsertFunction(lava_ret_str,
//         retFnTy);

//         /* Insert the call */
//         B.CreateCall(lava_arg_callee, { v, FuncNames[F] });
//     }
// }

// void basicblockEnum(BasicBlock &BB, IRBuilder<> &B, Module& M, LLVMContext&
// ctx, int64_t counter, Function * F) {
//     /* Create a new LLVM obj that stores */
//     ConstantInt* BB_index = ConstantInt::get(IntegerType::get(ctx, 64),
//     counter);

//     /* Create runtime function call for the basic block */
//     std::string lava_bb_inst_str = "libresolve_bb";

//     /* Declare the function type of the function call */
//     FunctionType* voidFnTy = FunctionType::get(
//                 Type::getVoidTy(ctx),
//                 { IntegerType::get(ctx, 64), PointerType::get(ctx, 0) },
//                 false
//     );

//     FunctionCallee lava_bb_callee = M.getOrInsertFunction(lava_bb_inst_str,
//     voidFnTy); B.CreateCall(lava_bb_callee, { BB_index, FuncNames[F] });

//     return;
// }

// PreservedAnalyses AnnotateFunctions::run(Module &M, ModuleAnalysisManager
// &MAM) {
//     LLVMContext& ctx = M.getContext();

//     /* Loop over each function definition */
//     for (Function& F: M) {
//         /* Skip function declarations */
//         if (F.isDeclaration()) { continue; }

//         /* Look up function name in hashmap */
//         getFunctionNameGlobal(M, F, ctx);

//         /* Initialize a counter keep track of basic block indices */
//         int64_t BB_index = 0;

//         /* Get the pointer to the entry block of each function */
//         BasicBlock &entry = F.getEntryBlock();
//         Instruction* insertBeforePt = &*entry.getFirstInsertionPt();

//         /* Initialize a builder object to insert special libresolve
//         instruction */ IRBuilder<> builder(insertBeforePt);

//         for(Argument& arg: F.args()) {
//             /* insert an instruction with the correct type info. */
//             emitLavaArg(&arg, builder, M, ctx, &F);
//         }

//         /* Initialize a vector to store pointers to each basic block */
//         std::vector<BasicBlock*> BB_collection;
//         for (auto& BB : F) {
//             BB_collection.push_back(&BB);
//         }

//         for(BasicBlock* BB : BB_collection) {
//             Instruction* insertBBInst = &*BB->getFirstInsertionPt();
//             IRBuilder<> bb_builder(insertBBInst);

//             basicblockEnum(*BB, bb_builder, M, ctx, BB_index++,
//             BB->getParent());

//             if (auto* lava_ret_inst =
//             dyn_cast<ReturnInst>(BB->getTerminator())) {
//                 IRBuilder<> rb(lava_ret_inst);
//                 emitLavaRetVal(lava_ret_inst->getReturnValue(), rb, M, ctx,
//                 &F);
//             }
//         }
//     }
//     // IR has been modified
//     return PreservedAnalyses::none();
// }

/* New PM Registration */
PassPluginLibraryInfo getAnnotateFunctionsInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AnnotateFunctions", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(AnnotateFunctions());
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getAnnotateFunctionsInfo();
}
