#include <stdlib.h>

int main() {
    int* px = malloc(sizeof(int));
    double* py = malloc(sizeof(double));
    *px = 4;

    //printf("Value is %d\n", *px);
    free(px);
    free(py);
    return 0;
}