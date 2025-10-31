// #include <stdlib.h>
// int loop(int *array) {
//     int *ptr = array;
//     while (*ptr < 200) {
//         ptr+=1;
//     }
//     return *ptr;
// }

// int foo(int *array) {
//     return array[2];
// }

int main(void) {
    int a[3] = {0, 1, 2};
    int b[3] = {4, 5, 6};
    int arr[2] = {4, 5};
    int x = arr[3];
    int y = 7;
    b[3] = y;

    return a[3];
}