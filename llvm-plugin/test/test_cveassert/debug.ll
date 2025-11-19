; ModuleID = 'debug.c'
source_filename = "debug.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@DEBUG_APP_Data = dso_local global i8 0, align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @DEBUG_APP_CrashCmd(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  call void @resolve_sanitize_null_ptr_st_ptr(ptr %2, ptr %0)
  %4 = call i8 @resolve_sanitize_null_ptr_ld_i8(ptr @DEBUG_APP_Data)
  %5 = add i8 %4, 1
  call void @resolve_sanitize_null_ptr_st_i8(ptr @DEBUG_APP_Data, i8 %5)
  %6 = call ptr @resolve_sanitize_null_ptr_ld_ptr(ptr %2)
  call void @resolve_sanitize_null_ptr_st_ptr(ptr %3, ptr %6)
  %7 = call ptr @resolve_sanitize_null_ptr_ld_ptr(ptr %3)
  %8 = getelementptr inbounds i8, ptr %7, i64 0
  call void @resolve_sanitize_null_ptr_st_i8(ptr %8, i8 97)
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  call void @DEBUG_APP_CrashCmd(ptr noundef null)
  ret i32 0
}

define weak void @resolve_report_sanitizer_triggered() {
  ret void
}

define internal i8 @resolve_sanitize_null_ptr_ld_i8(ptr %0) {
  %2 = icmp eq ptr %0, null
  br i1 %2, label %3, label %4

3:                                                ; preds = %1
  call void @resolve_report_sanitizer_triggered()
  ret i8 0

4:                                                ; preds = %1
  %5 = load i8, ptr %0, align 1
  ret i8 %5
}

define internal ptr @resolve_sanitize_null_ptr_ld_ptr(ptr %0) {
  %2 = icmp eq ptr %0, null
  br i1 %2, label %3, label %4

3:                                                ; preds = %1
  call void @resolve_report_sanitizer_triggered()
  ret ptr null

4:                                                ; preds = %1
  %5 = load ptr, ptr %0, align 8
  ret ptr %5
}

define internal void @resolve_sanitize_null_ptr_st_ptr(ptr %0, ptr %1) {
  %3 = icmp eq ptr %0, null
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  call void @resolve_report_sanitizer_triggered()
  ret void

5:                                                ; preds = %2
  store ptr %1, ptr %0, align 8
  ret void
}

define internal void @resolve_sanitize_null_ptr_st_i8(ptr %0, i8 %1) {
  %3 = icmp eq ptr %0, null
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  call void @resolve_report_sanitizer_triggered()
  ret void

5:                                                ; preds = %2
  store i8 %1, ptr %0, align 1
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
