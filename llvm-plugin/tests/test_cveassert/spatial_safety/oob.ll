; ModuleID = 'oob.c'
source_filename = "oob.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@__const.main.a = private unnamed_addr constant [3 x i32] [i32 0, i32 1, i32 2], align 4
@__const.main.arr = private unnamed_addr constant [2 x i32] [i32 4, i32 5], align 4
@_start = external global i8
@_end = external global i8

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @loop(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  store ptr %4, ptr %3, align 8
  br label %5

5:                                                ; preds = %9, %1
  %6 = load ptr, ptr %3, align 8
  %7 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %6)
  %8 = icmp slt i32 %7, 200
  br i1 %8, label %9, label %12

9:                                                ; preds = %5
  %10 = load ptr, ptr %3, align 8
  %11 = getelementptr inbounds i32, ptr %10, i64 1
  store ptr %11, ptr %3, align 8
  br label %5, !llvm.loop !6

12:                                               ; preds = %5
  %13 = load ptr, ptr %3, align 8
  %14 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %13)
  ret i32 %14
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @foo(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = getelementptr inbounds i32, ptr %3, i64 2
  %5 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %4)
  ret i32 %5
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca [3 x i32], align 4
  %3 = alloca [2 x i32], align 4
  %4 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %2, ptr align 4 @__const.main.a, i64 12, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %3, ptr align 4 @__const.main.arr, i64 8, i1 false)
  %5 = getelementptr inbounds [2 x i32], ptr %3, i64 0, i64 1
  %6 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %3, ptr %5)
  store i32 %6, ptr %4, align 4
  %7 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 3
  %8 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %2, ptr %7)
  ret i32 %8
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #1

define internal ptr @resolve_sanitize_bounds_ld_ptr(ptr %0, ptr %1) {
  %3 = call i1 @resolve_is_heap(ptr %0)
  br i1 %3, label %10, label %7

4:                                                ; preds = %10
  call void @log_sanitize_block(ptr %0)
  ret ptr null

5:                                                ; preds = %12, %10
  %6 = load ptr, ptr %1, align 8
  ret ptr %6

7:                                                ; preds = %2
  %8 = call i1 @resolve_is_heap(ptr %1)
  %9 = and i1 %3, %8
  br i1 %9, label %10, label %12

10:                                               ; preds = %7, %2
  %11 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %11, label %5, label %4

12:                                               ; preds = %7
  br label %5
}

define internal i1 @resolve_is_heap(ptr %0) {
  %2 = call ptr asm sideeffect "mov %rsp, $0", "=r,~{dirflag},~{fpsr},~{flags}"()
  %3 = icmp ule ptr %2, %0
  %4 = icmp uge ptr %0, @_start
  %5 = icmp ule ptr %0, @_end
  %6 = and i1 %4, %5
  %7 = or i1 %3, %6
  %8 = xor i1 %7, true
  ret i1 %8
}

declare i1 @resolve_check_bounds(ptr, ptr)

declare void @log_sanitize_block(ptr)

define internal i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %1) {
  %3 = call i1 @resolve_is_heap(ptr %0)
  br i1 %3, label %10, label %7

4:                                                ; preds = %10
  call void @log_sanitize_block(ptr %0)
  ret ptr null

5:                                                ; preds = %12, %10
  %6 = load i32, ptr %1, align 4
  ret i32 %6

7:                                                ; preds = %2
  %8 = call i1 @resolve_is_heap(ptr %1)
  %9 = and i1 %3, %8
  br i1 %9, label %10, label %12

10:                                               ; preds = %7, %2
  %11 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %11, label %5, label %4

12:                                               ; preds = %7
  br label %5
}

define internal void @resolve_sanitize_bounds_st_ptr(ptr %0, ptr %1, ptr %2) {
  %4 = call i1 @resolve_is_heap(ptr %0)
  br i1 %4, label %10, label %7

5:                                                ; preds = %10
  call void @log_sanitize_block(ptr %0)
  ret void

6:                                                ; preds = %12, %10
  store ptr %2, ptr %1, align 8
  ret void

7:                                                ; preds = %3
  %8 = call i1 @resolve_is_heap(ptr %1)
  %9 = and i1 %4, %8
  br i1 %9, label %10, label %12

10:                                               ; preds = %7, %3
  %11 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %11, label %6, label %5

12:                                               ; preds = %7
  br label %6
}

define internal void @resolve_sanitize_bounds_st_i32(ptr %0, ptr %1, i32 %2) {
  %4 = call i1 @resolve_is_heap(ptr %0)
  br i1 %4, label %10, label %7

5:                                                ; preds = %10
  call void @log_sanitize_block(ptr %0)
  ret void

6:                                                ; preds = %12, %10
  store i32 %2, ptr %1, align 4
  ret void

7:                                                ; preds = %3
  %8 = call i1 @resolve_is_heap(ptr %1)
  %9 = and i1 %4, %8
  br i1 %9, label %10, label %12

10:                                               ; preds = %7, %3
  %11 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %11, label %6, label %5

12:                                               ; preds = %7
  br label %6
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
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
