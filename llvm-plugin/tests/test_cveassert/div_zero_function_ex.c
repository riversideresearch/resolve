#include <stdio.h>
#include <assert.h>

static int opj_int_ceildiv(int a, int b) {
    assert(b);
    return (a + b - 1) / b;
}

int main() {
    int x = 10;
    int y = 1 - 1;

    int res = opj_int_ceildiv(x, y);
    return res;
}