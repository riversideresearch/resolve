#include <stdlib.h>
#include <stdio.h>

int global_x;

void use_x(int *x) {
    printf("%lx\n", x);
    free(x);
}

extern char _edata, _etext, _end, _start;

int main(void) {
    int x;
    
    printf("%lx\n", &_start);
    printf("%lx\n", &_etext);
    printf("%lx\n", &_edata);
    printf("%lx\n\n", &_end);
    use_x(&x);
    use_x(&global_x);
    use_x(malloc(4));
}
