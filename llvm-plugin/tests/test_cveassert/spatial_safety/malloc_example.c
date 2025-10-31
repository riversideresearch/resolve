#include <stdio.h>
#include <stdlib.h>


int main(void) {
    int *arr = malloc(3 * sizeof(int));
    arr[0] = 0;
    arr[1] = 1;
    arr[2] = 2;
    
    return arr[3];
}