// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @main
// CHECK: call void @resolve_stack_obj
 
#include <stdio.h>

int main() {
  int arr[2] = { 0, 1 };
  int x = arr[3];

  return x;

}
