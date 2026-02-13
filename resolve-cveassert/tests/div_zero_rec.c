/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// RUN: RESOLVE_LABEL_CVE=vulnerabilities/div_zero_rec_vuln.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK-LABEL: define dso_local i32 @div_zero_main 
// CHECK: call void @resolve_report_sanitizer_triggered
// CHECK: call void @resolve_remediation_behavior 
// CHECK-LABEL: define dso_local i32 @main
// CHECK: call i32 @_setjmp 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/div_zero_rec_vuln.json %clang -fpass-plugin=%plugin %s -o %t.exe
// RUN: %t.exe 1; test $? -eq 0
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

static jmp_buf recover_longjmp_buf;

jmp_buf* resolve_get_recover_longjmp_buf() {
    return &recover_longjmp_buf;
}

void resolve_report_sanitizer_triggered() { printf("Calling sanitizer!\n"); }

int div_zero_main(int argc, const char* argv[]) {        
    int math = (int) (42.0 / (float)argc);
    return 42 % argc + math / argc;
}

void error_handler() {
    printf("Should see this print before exiting program\n");
}

int main(int argc, const char* argv[]) {
    // NOTE: call with 1 arg to trigger div by zero
    int x = setjmp(*resolve_get_recover_longjmp_buf());
    if (x > 0) {
        error_handler();
    } else {
        printf("Attempting division...\n");
        int res = div_zero_main(argc-2, argv);
        printf("Result: %d\n", res); // Does not print 
    }
}
