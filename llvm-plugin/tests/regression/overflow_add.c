#include <stdio.h>
#include <limits.h>
// RUN: RESOLVE_STRATEGY=SAT RESOLVE_LABEL_CVE=vulnerabilities/overflow_add_vuln.json \
// RUN:  %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @main
// CHECK: call { i32, i1 } @llvm.sadd.with.overflow.i32
// CHECK: call void @resolve_report_sanitizer_triggered
int main(void) {
    int a = INT_MAX;
    int b = 1;
    int sum = a + b;
    return 0;
}