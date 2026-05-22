static int checksum(const char *data, unsigned long len) {
    int sum = 0;
    for (unsigned long i = 0; i <= len; ++i) {
        sum += data[i];
    }
    return sum;
}

int parse_frame(const char *input) {
    char frame[8];
    for (int i = 0; i < 9; ++i) {
        frame[i] = input[i];
    }
    return checksum(frame, 12);
}

int main(void) {
    return parse_frame("ABCDEFGH");
}
