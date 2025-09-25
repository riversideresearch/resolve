#include <stdio.h>
#include <stdlib.h>

void increment_arr(int* a, int size) {
    int* ptr = a;
    while (ptr < a + size) {
        *ptr += 1;
        ptr++;
    }
}

void print_arr(int* arr, int size) {
    int* ptr = arr;
    while( ptr < arr + size) {
        printf("%d ", *ptr);
        ptr++;
    }
}

int main(void) {
    int arr[3] = {0, 1, 2};
    int b[3] = {3, 4, 5};

    int size_arr = sizeof(arr) / sizeof(arr[0]);
    int size_b = sizeof(b) / sizeof(b[0]);

    increment_arr(arr, size_arr);
    print_arr(arr, size_arr);

    increment_arr(b, size_b);
    print_arr(b, size_b);

    return arr[3];
}