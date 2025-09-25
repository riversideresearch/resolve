; ModuleID = 'stack_free.c'
source_filename = "stack_free.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [5 x i8] c"%lx\0A\00", align 1
@_start = external global i8, align 1
@_etext = external global i8, align 1
@_edata = external global i8, align 1
@.str.1 = private unnamed_addr constant [6 x i8] c"%lx\0A\0A\00", align 1
@_end = external global i8, align 1
@global_x = dso_local global i32 0, align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @use_x(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = call i32 (ptr, ...) @printf(ptr noundef @.str, ptr noundef %3)
  %5 = load ptr, ptr %2, align 8
  call void @resolve_sanitize_non_heap_free(ptr %5)
  ret void
}

declare i32 @printf(ptr noundef, ...) #1

; Function Attrs: nounwind
declare void @free(ptr noundef) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = call i32 (ptr, ...) @printf(ptr noundef @.str, ptr noundef @_start)
  %3 = call i32 (ptr, ...) @printf(ptr noundef @.str, ptr noundef @_etext)
  %4 = call i32 (ptr, ...) @printf(ptr noundef @.str, ptr noundef @_edata)
  %5 = call i32 (ptr, ...) @printf(ptr noundef @.str.1, ptr noundef @_end)
  call void @use_x(ptr noundef %1)
  call void @use_x(ptr noundef @global_x)
  %6 = call noalias ptr @malloc(i64 noundef 4) #4
  call void @use_x(ptr noundef %6)
  ret i32 0
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #3

define internal void @resolve_sanitize_non_heap_free(ptr %0) {
  %2 = call i1 @resolve_is_heap(ptr %0)
  br i1 %2, label %4, label %3

3:                                                ; preds = %1
  ret void

4:                                                ; preds = %1
  call void @free(ptr %0)
  ret void
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

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind allocsize(0) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
