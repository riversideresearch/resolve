/*
    Copyright (c) 2025 Riverside Research.
    LGPL-3; See LICENSE.txt in the repo root for details.
*/

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>

// jump buffer for recovery
jmp_buf recover_longjmp_buf;

// required by resolve for recovery strategy
jmp_buf *resolve_get_recover_longjmp_buf() {
    return &recover_longjmp_buf;
}

int main(int argc, char** argv) {
    printf("Hello from example program!\n");

    // CWE-121: Stack-based Buffer Overflow
    // Stack buffer overflow via out-of-bounds array access
    if (argc > 1) {
        int idx = atoi(argv[1]);
        int buffer[10] = { 0 };

        // set recovery point
        if (setjmp(*resolve_get_recover_longjmp_buf())) {
            printf("RECOVERED: violation detected for index %d! Continuing execution...\n", idx);
            printf("Program recovered and exiting with code 1.\n");
            return 1;
        }

        printf("Accessing buffer at index: %d\n", idx);
        buffer[idx] = 42;  // UNSAFE: No bounds checking on array access!

        printf("Successfully wrote to buffer[%d]\n", idx);
        printf("Value at buffer[%d] = %d\n", idx, buffer[idx]);
    } else {
        printf("Pass an index to access the buffer (valid range: 0-9).\n");
    }

    return 0;
}
