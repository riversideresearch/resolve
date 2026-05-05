/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/vla_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK: call void @__resolve_alloca
//
// Test that the remediation is successful
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/vla_oob.json %clang -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

void example(int n) {
    int arr[n];
    for (int i = 0; i <= n; ++i) {
        arr[i] = i;
    }
}

int main() {
    int n = 5;
    example(n);
    return 0;
}

