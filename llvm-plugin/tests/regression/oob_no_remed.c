/*
 *   Copyright (c) 2025 Riverside Research.
 *   See LICENSE.txt in the repo root for licensing information.
 */

// RUN: %clang -S -emit-llvm \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: dso_local i32 @main
// CHECK-NOT: call ptr @resolve_sanitize_memcpy

#include <stdlib.h>
int loop(int *array) {
    int *ptr = array;
    while (*ptr < 200) {
        ptr+=1;
    }
    return *ptr;
}

int foo(int *array) {
    return array[2];
}

int main(void) {
    int a[3] = {0, 1, 2};
    int arr[2] = {4, 5};
    int x = arr[1];

    return a[3];
}