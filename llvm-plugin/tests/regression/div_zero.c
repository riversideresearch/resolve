/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/div_zero_vuln.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @div_zero_main 
// CHECK: call void @resolve_report_sanitizer_triggered
// CHECK: icmp eq i32 
// CHECK-LABEL: define dso_local i32 @main
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/div_zero_vuln.json %clang -fpass-plugin=%plugin %s -o %t.exe 
// RUN: %t.exe 1 || true
// RUN: echo $? 
#include <stdio.h>
#include <stdlib.h>

void resolve_report_sanitizer_triggered(void) { printf("Calling sanitizer!\n"); }

int div_zero_main(int argc, const char* argv[]) {        
    int math = (int) (42.0 / (float)argc);
    return 42 % argc + math / argc;
}

int main(int argc, const char* argv[]) {
    // NOTE: call with 1 arg to trigger div by zero
    return div_zero_main(argc-2, argv);
}