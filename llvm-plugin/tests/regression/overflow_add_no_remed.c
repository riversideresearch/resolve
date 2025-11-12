/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for licensing information.
 */

// RUN: %clang -S -emit-llvm \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: dso_local i32 @main
// CHECK-NOT: call { i32, i1 } @llvm.sadd.with.overflow.i32
// CHECK-NOT: call void @resolve_report_sanitizer_triggered

#include <stdio.h>
#include <limits.h>

int main(void) {
    int a = INT_MAX;
    int b = 1;

    int sum = a + b;

    return 0;
} 