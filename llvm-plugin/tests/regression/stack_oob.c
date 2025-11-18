/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @main
// CHECK: call void @resolve_stack_obj
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; test $? -eq 3
 
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
  int i;
  int idx = atoi(argv[0]);
  int buffer[10] = { 0 };

  if (idx >= 0) {
    buffer[idx] = 1;

    for (i = 0; i < 10; ++i) {
      printf("%d ", buffer[i]);
    }
    return 0;
  
  } else {
    printf("ERROR: Negative indexing results in OOB access: %d", idx);
    return -1;
  }
}
