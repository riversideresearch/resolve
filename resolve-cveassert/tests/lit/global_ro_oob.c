/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// Check the constant global is registered (constants are intentionally kept)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/global_ro_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s
// CHECK: @llvm.global_ctors ={{.*}}@__resolve_register_globals_ctor
// CHECK: call void @__resolve_register_global(ptr @secret
//
// Test that the remediation is successful (out-of-bounds read)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/global_ro_oob.json %clang -O0 -g -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 50; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3
//
// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/global_ro_oob.json %clang -O3 -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 50; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3
//
// Test that the normal behavior is preserved
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/global_ro_oob.json %clang -O0 -g -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 2; EXIT_CODE=$?; \
// RUN: echo Normal exit: $EXIT_CODE; test $EXIT_CODE -eq 33

#include <stdio.h>
#include <stdlib.h>

const int secret[4] = { 11, 22, 33, 44 };

int read_global(int idx) {
  return secret[idx];
}

int main(int argc, char *argv[]) {
  int idx = atoi(argv[1]);
  return read_global(idx);
}
