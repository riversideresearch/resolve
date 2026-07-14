#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[8];
    strcpy(buf, name);
    printf("Hello, %s!\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 0;
    greet(argv[1]);
    return 0;
}
