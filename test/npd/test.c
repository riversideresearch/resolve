#include <stdio.h>

const char *greeting = "hello\n";

void do_npd(void) {
    printf(greeting);
    // int *i = 0;
    // *i = 10;
}

void main(void) {
    do_npd();
}