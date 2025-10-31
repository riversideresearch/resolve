#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define a struct to hold information about a person
typedef struct {
    char name[50];
    int age;
} Person;

// Function to find the oldest person in the array
Person* findOldest(Person* people, size_t count) {
    if (count == 0) return NULL;

    Person* oldest = &people[0];  // start with the first person
    for (size_t i = 1; i < count; ++i) {
        if (people[i].age > oldest->age) {
            oldest = &people[i];  // update pointer if this person is older
        }
    }
    return oldest;
}

int main() {
    size_t numPeople = 3;
    Person* people = malloc(numPeople * sizeof(Person));  // dynamically allocate memory for 3 people

    if (people == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Populate the array
    strcpy(people[0].name, "Alice");
    people[0].age = 30;

    strcpy(people[1].name, "Bob");
    people[1].age = 45;

    strcpy(people[2].name, "Charlie");
    people[2].age = 25;

    // Find the oldest person
    Person* oldest = findOldest(people, numPeople);

    if (oldest != NULL) {
        printf("Oldest person: %s (%d years old)\n", oldest->name, oldest->age);
    }

    free(people);  // don't forget to free allocated memory
    return 0;
}