#include <string.h>
#include <stdlib.h>

int main() {
	int x = 10;
	char* string_ptr = "Hello, World";
	char *buffer = malloc(10 * sizeof(char));
	char *ptr = memcpy(buffer, string_ptr, strlen(string_ptr) + x);
}
