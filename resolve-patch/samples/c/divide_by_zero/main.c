static int parse_count(int value) {
    return value - 1;
}

int compute_ratio(int total, int input) {
    int divisor = parse_count(input);
    int quotient = total / divisor;
    int remainder = total % divisor;
    return quotient + remainder;
}

int main(void) {
    return compute_ratio(42, 1);
}
