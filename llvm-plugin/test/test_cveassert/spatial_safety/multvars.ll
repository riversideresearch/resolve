; ModuleID = 'multvars.c'
source_filename = "multvars.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@__const.main.a = private unnamed_addr constant [3 x i32] [i32 0, i32 1, i32 2], align 4
@__const.main.b = private unnamed_addr constant [3 x i32] [i32 4, i32 5, i32 6], align 4
@__const.main.arr = private unnamed_addr constant [2 x i32] [i32 4, i32 5], align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca [3 x i32], align 4
  %3 = alloca [3 x i32], align 4
  %4 = alloca [2 x i32], align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %2, ptr align 4 @__const.main.a, i64 12, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %3, ptr align 4 @__const.main.b, i64 12, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %4, ptr align 4 @__const.main.arr, i64 8, i1 false)
  %7 = getelementptr inbounds [2 x i32], ptr %4, i64 0, i64 3
  %8 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %4, ptr %7)
  store i32 %8, ptr %5, align 4
  store i32 7, ptr %6, align 4
  %9 = load i32, ptr %6, align 4
  %10 = getelementptr inbounds [3 x i32], ptr %3, i64 0, i64 3
  call void @resolve_sanitize_bounds_st_i32(ptr %3, ptr %10, i32 %9)
  %11 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 3
  %12 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %2, ptr %11)
  ret i32 %12
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #1

define internal i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %1) {
  %3 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %3, label %5, label %4

4:                                                ; preds = %2
  ret void

5:                                                ; preds = %2
  %6 = load i32, ptr %1, align 4
  ret i32 %6
}

declare i1 @resolve_check_bounds(ptr, ptr)

define internal void @resolve_sanitize_bounds_st_i32(ptr %0, ptr %1, i32 %2) {
  %4 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %4, label %6, label %5

5:                                                ; preds = %3
  ret void

6:                                                ; preds = %3
  store i32 %2, ptr %1, align 4
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
