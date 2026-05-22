static int shift_amount(int width, int offset) {
    return width + offset;
}

unsigned int encode_flags(unsigned int flags, int offset) {
    int amount = shift_amount(32, offset);
    return flags << amount;
}

int main(void) {
    return (int)encode_flags(3u, 1);
}
