#include <stdio.h>
#include <string.h>

void parse_record(const unsigned char *payload, unsigned char len) {
    char buf[16];
    memcpy(buf, payload, len);
    printf("parsed %u bytes\n", len);
}

int main(void) {
    unsigned char data[256];
    size_t n = fread(data, 1, sizeof data, stdin);
    if (n < 1)
        return 0;
    parse_record(data + 1, data[0]);
    return 0;
}
