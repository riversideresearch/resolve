/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/heap_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @main
// CHECK: call ptr @resolve_malloc 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/heap_oob.json %clang -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: RUST_LOG=off %t.exe; test $? -eq 3

#include <stdio.h>
#include <stdlib.h>
int main() {
    int *ptr = malloc(2 * sizeof(int));
    ptr[0] = 1;
    ptr[1] = 10;
    ptr[2] = 5;

    int x = ptr[2]; 
    return x;

}
