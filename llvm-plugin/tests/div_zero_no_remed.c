// RUN: %clang -S -emit-llvm %s -o - | %FileCheck %s
// CHECK-LABEL: define dso_local i32 @div_zero_main
// CHECK: sdiv i32 
// CHECK-NOT: call void resolve_report_sanitizer_triggered
// CHECK-LABEL: define dso_local i32 @main
// RUN: %clang %s -o %t.exe
// RUN: ! %t.exe 1
#include <stdlib.h>

int div_zero_main(int argc, const char* argv[]) {
    int math = (int) (42.0 / (float)argc);
    return 42 % argc + math / argc;
}

int main(int argc, const char* argv[]) {
    // NOTE: call with 1 arg to trigger div by zero
    return div_zero_main(argc-2, argv);
}