; ModuleID = 'div_zero.c'
source_filename = "div_zero.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @div_zero_main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store ptr %1, ptr %4, align 8
  %6 = load i32, ptr %3, align 4
  %7 = sitofp i32 %6 to float
  %8 = fpext float %7 to double
  %9 = fcmp oeq double %8, 0.000000e+00
  br i1 %9, label %12, label %10

10:                                               ; preds = %2
  %11 = fdiv double 4.200000e+01, %8
  br label %13

12:                                               ; preds = %2
  call void @resolve_report_sanitizer_triggered()
  br label %13

13:                                               ; preds = %10, %12
  %14 = phi double [ 4.200000e+01, %12 ], [ %11, %10 ]
  %15 = fptosi double %14 to i32
  store i32 %15, ptr %5, align 4
  %16 = load i32, ptr %3, align 4
  %17 = srem i32 42, %16
  %18 = load i32, ptr %5, align 4
  %19 = load i32, ptr %3, align 4
  %20 = icmp eq i32 %19, 0
  br i1 %20, label %23, label %21

21:                                               ; preds = %13
  %22 = sdiv i32 %18, %19
  br label %25

23:                                               ; preds = %13
  call void @resolve_report_sanitizer_triggered()
  %24 = sdiv i32 %18, 1
  br label %25

25:                                               ; preds = %21, %23
  %26 = phi i32 [ %24, %23 ], [ %22, %21 ]
  %27 = add nsw i32 %17, %26
  ret i32 %27
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store i32 0, ptr %3, align 4
  store i32 %0, ptr %4, align 4
  store ptr %1, ptr %5, align 8
  %6 = load i32, ptr %4, align 4
  %7 = sub nsw i32 %6, 2
  %8 = load ptr, ptr %5, align 8
  %9 = call i32 @div_zero_main(i32 noundef %7, ptr noundef %8)
  ret i32 %9
}

define weak void @resolve_report_sanitizer_triggered() {
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
