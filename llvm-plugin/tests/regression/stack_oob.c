/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @main
// CHECK-LABEL: call void @resolve_stack_obj
// Test that that unremediated case crashes
// RUN: %clang -fpass-plugin=%plugin %s -o %t.exe 
// RUN: %t.exe -2; EXIT_CODE=$?; \
// RUN: echo Unremedated exit: $EXIT_CODE; test $EXIT_CODE -ne 0
//
// Test that the remediation is successful
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe -2; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3
// 
// Test that the normal behavior is preserved
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe 2; EXIT_CODE=$?; \
// RUN: echo Normal exit: $EXIT_CODE; test $EXIT_CODE -eq 0

#include <stdio.h>
#include <stdlib.h>

int use_stack(int buffer[], int idx) {
  int i;
  buffer[idx] = 42;

  for (i = 0; i < 10; ++i) {
    printf("%d \n", buffer[i]);
  }

  return buffer[idx];
}

int main(int argc, char *argv[]) {
  int idx = atoi(argv[1]);
  int buffer[10] = { 0 };

  return use_stack(buffer, idx);
}
