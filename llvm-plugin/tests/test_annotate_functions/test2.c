#include <stdio.h>
#include <stdlib.h>

// Function to fill an array with values
typedef struct Car {
    char* model;
    int year;
} Car_t;


void updateCar(Car_t* car, int year) {
    car->year = year;
}

int main(int argc, char** argv){
    // Initialize a new car instance.
    Car_t* nissan = malloc(sizeof(Car_t)); 
    nissan->model = "Nissan";
    nissan->year = 2005;

    updateCar(nissan, 2020);

    free(nissan);
    return 0;
}