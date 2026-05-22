extern void *malloc(unsigned long size);
extern void free(void *ptr);

static void fill_payload(char *dst, unsigned long capacity) {
    for (unsigned long i = 0; i <= capacity + 3; ++i) {
        dst[i] = (char)('A' + (i % 26));
    }
}

int decode_packet(unsigned long payload_size) {
    char *payload = (char *)malloc(payload_size);
    if (!payload) {
        return 1;
    }
    fill_payload(payload, payload_size);
    int value = payload[payload_size + 1];
    free(payload);
    return value;
}

int main(void) {
    return decode_packet(8);
}
