// Test that the remediation is successful 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memcpy_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK: call ptr @resolve_bounds_check_memcpy 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memcpy_oob.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; test $? -eq 3

// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memcpy_oob.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3


#include <stdlib.h>
#include <string.h>

int main() {
    char *x, *y;
    x = malloc(8);
    y = malloc(3);
    
    for (size_t i = 0; i < 8; ++i) {
        x[i] = (char)i;
    }

    memcpy(y, x, 5);

    free(x);
    free(y);

    return 0;
}