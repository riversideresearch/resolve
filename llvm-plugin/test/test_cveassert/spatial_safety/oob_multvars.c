// #include <stdlib.h>
// int loop(int *array) {
//     int *ptr = array;
//     while (*ptr < 200) {
//         ptr+=1;
//     }
//     return *ptr;
// }
#include <stdlib.h>


int foo(int *arr1, int* arr2) {
    for(int* ptr1 = arr1; *ptr1 != NULL; ptr1++) {
        for(int* ptr2 = arr2; *ptr2 != NULL; ptr2++) {
            if (*ptr1 == *ptr2) {
                return *ptr1;
            }
        }
    }
}

int main(void) {
    int a[3] = {0, 1, 2};
    int b[3] = {4, 5, 6};
    int arr[2] = {4, 5};
    int x = arr[3];
    int y = 7;
    b[3] = y;

    int res = foo(a, b);

    return a[3];
}