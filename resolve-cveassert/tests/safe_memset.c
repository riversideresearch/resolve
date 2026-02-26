// Test that the remediation is successful (Normal exit code is returned)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/safe_memset.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK: call ptr @resolve_bounds_check_memset 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/memset_oob.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; test $? -eq 0

// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/safe_memset.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    size_t large_size = 16;

    char *buf = malloc(large_size);

    if (!buf) {
        perror("malloc failed");
        return 1;
    }

    // Writes 16-bytes into the 16-byte buffer (safe)
    memset(buf, 'A', large_size);

    printf("Done\n");
    free(buf);
    return 0;
}