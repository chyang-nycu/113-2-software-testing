#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// 定義 LLVMPass
struct LLVMPass : public PassInfoMixin<LLVMPass> {
  // run() 方法會在優化管線的最後階段被調用
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &Ctx = M.getContext();
    // i32 類型
    IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);

    // 獲取或插入 debug 函數的原型：int debug(int)
    FunctionCallee debugFunc =
        M.getOrInsertFunction("debug", Int32Ty, /*param*/ Int32Ty);
    // 創建常量 48763，用於 debug 調用和覆蓋 argc
    ConstantInt *const48763 = ConstantInt::get(Int32Ty, 48763);

    // 遍歷模組中的所有函數，找到 main
    for (Function &F : M) {
      if (F.getName() == "main") {
        // 獲取 main 的入口基本塊
        BasicBlock &entryBB = F.getEntryBlock();
        // 在第一個非 alloca 指令前創建 IRBuilder
        IRBuilder<> Builder(&*entryBB.getFirstInsertionPt());

        // 1) 在 main 開頭插入 debug(48763) 調用
        Builder.CreateCall(debugFunc, {const48763});

        // 2) 覆蓋 argc 參數為 48763
        Argument *argcArg = F.getArg(0);
        argcArg->replaceAllUsesWith(const48763);

        // 3) 覆蓋 argv[1] 為 "hayaku... motohayaku!"
        Argument *argvArg = F.getArg(1);
        // 在全局段中創建字符串常量，並返回 i8* 指針
        Constant *newStr =
            Builder.CreateGlobalStringPtr("hayaku... motohayaku!", "instr_str");
        // 構造索引常量 1
        ConstantInt *idxOne = ConstantInt::get(Int32Ty, 1);
        // 生成 getelementptr 指令，計算 argv + 1 的地址，類型為 i8**
        Value *gep = Builder.CreateInBoundsGEP(
            argvArg->getType()->getPointerElementType(), // 指針所指元素類型 i8*
            argvArg,
            idxOne,
            "argv1ptr");
        // 將 newStr 存入 argv[1]
        Builder.CreateStore(newStr, gep);
      }
    }

    // 因為我們改動了函數內部的 IR，標記所有分析均不再保留
    return PreservedAnalyses::none();
  }
};

// 註冊 Pass 插件
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
          [](PassBuilder &PB) {
            // 在優化管線最後階段插入我們的 LLVMPass
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(LLVMPass());
                });
          }};
}
