#include <stdio.h>

int should_run = 0xFFFFAAAA;

int main(void) {
    if (should_run & 0x01) {
        puts("Hello!\n");
    }
}