// Test that the remediation is successful (exits with code 3)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/buffer_overflow.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// CHECK: call ptr @resolve_bounds_check_memcpy 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/buffer_overflow.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe input.bin; test $? -eq 3

// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/buffer_overflow.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe input.bin; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

void vuln(FILE* fd)
{
    fseek(fd, 0, SEEK_END);
    size_t fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // overflow a buffer
    char* full = malloc(fsize);
    char tiny[16];
    fread(full, 1, fsize, fd);
    memcpy(tiny, full, fsize);
    printf("Tiny: %s\n", tiny);
    free(full);
}

void check(char* input, FILE* fd)
{
    // input == "KILL"
    if(input[0] != 'K')
        return;
    if(input[1] != 'I')
        return;
    if(input[2] != input[3])
        return;
    if(input[3] != 'L')
        return;
    
    vuln(fd);
    return;

}

int main(int argc, char **argv)
{
    FILE*   fd = 0;
    char    input[10];
    memset(input, 0, sizeof(input));
    int     n;
    if (argc == 2) {
        if ((fd = fopen(argv[1], "rb")) < 0) {
            exit(-1);
        }
        if ((n = fread(input, 1, 10, fd)) < 1) {
            return 1;
        }
    } else {
        exit(-1);
    }

    check(input, fd);
    return 0;
}