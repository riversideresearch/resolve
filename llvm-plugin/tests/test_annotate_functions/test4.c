/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

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