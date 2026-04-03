/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// Test that that unremediated case crashes
// RUN: %clang -fpass-plugin=%plugin %s -o %t.exe 
// RUN: %t.exe -2; EXIT_CODE=$?; \
// RUN: echo Unremedated exit: $EXIT_CODE; test $EXIT_CODE -ne 0
//
// Test that the remediation is successful
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/overflow_widen.json %clang -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 11; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 0
//
// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/overflow_widen.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 11; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 0

#include <stdio.h>
#include <assert.h>

int main(void) {
    unsigned long long n = 0x80000005;
    int sep = 0x40000000;

    unsigned long long start = 2*(2 + sep);
    unsigned long long len = n - 2*(2 + sep);
    
    printf("%llx, %llx\n", start, len);

    assert(1 == len);
}