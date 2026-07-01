#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("Hello, UB!\n");
    int r = *(int*)0x0; // guaranteed segfault
    printf("Oh, I didn't crash?\n");
    return 0;
}