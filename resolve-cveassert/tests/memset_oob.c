// Test that the remediation is successful 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memset_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK: call ptr @resolve_bounds_check_memset 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memset_oob.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; test $? -eq 3

// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memset_oob.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    size_t small_size = 16;
    size_t large_size = 64;

    char *buf = malloc(small_size);

    if (!buf) {
        perror("malloc failed");
        return 1;
    }

    // Writes 64-bytes into the 16-byte buffer (OOB)
    memset(buf, 'A', large_size);

    printf("Done\n");
    free(buf);
    return 0;
}