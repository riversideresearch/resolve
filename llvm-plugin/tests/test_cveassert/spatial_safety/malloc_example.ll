; ModuleID = 'malloc_example.c'
source_filename = "malloc_example.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@_start = external global i8
@_end = external global i8

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  %3 = call ptr @resolve_malloc(i64 12)
  store ptr %3, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  %5 = getelementptr inbounds i32, ptr %4, i64 0
  call void @resolve_sanitize_bounds_st_i32(ptr %3, ptr %5, i32 0)
  %6 = load ptr, ptr %2, align 8
  %7 = getelementptr inbounds i32, ptr %6, i64 1
  call void @resolve_sanitize_bounds_st_i32(ptr %3, ptr %7, i32 1)
  %8 = load ptr, ptr %2, align 8
  %9 = getelementptr inbounds i32, ptr %8, i64 2
  call void @resolve_sanitize_bounds_st_i32(ptr %3, ptr %9, i32 2)
  %10 = load ptr, ptr %2, align 8
  %11 = getelementptr inbounds i32, ptr %10, i64 3
  %12 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %3, ptr %11)
  ret i32 %12
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #1

define weak ptr @resolve_malloc(i64 %0) {
  %2 = call ptr @malloc(i64 %0)
  ret ptr %2
}

define weak ptr @resolve_calloc(i64 %0, i64 %1) {
  %3 = call ptr @calloc(i64 %0, i64 %1)
  ret ptr %3
}

declare ptr @calloc(i64, i64)

define weak ptr @resolve_realloc(ptr %0, i64 %1) {
  %3 = call ptr @realloc(ptr %0, i64 %1)
  ret ptr %3
}

declare ptr @realloc(ptr, i64)

define weak void @resolve_free(ptr %0) {
  call void @free(ptr %0)
  ret void
}

declare void @free(ptr)

define weak ptr @resolve_strdup(ptr %0) {
  %2 = call ptr @strdup(ptr %0)
  ret ptr %2
}

declare ptr @strdup(ptr)

define weak ptr @resolve_strndup(ptr %0, i64 %1) {
  %3 = call ptr @strndup(ptr %0, i64 %1)
  ret ptr %3
}

declare ptr @strndup(ptr, i64)

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

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
