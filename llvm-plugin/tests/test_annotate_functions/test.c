#include <stdlib.h>

typedef struct {
    int a, b;
} my_t;

my_t *global;

my_t *new() {
    return malloc(sizeof(my_t));
}

int foo() {
    return global->b;
}

void initialize(my_t *t) {
    t->a = 42;
    t->b = 38;
}

int main() {
    global = new();
    initialize(global);

    return foo();
}
