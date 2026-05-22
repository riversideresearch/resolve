#define INT_MAX_VALUE 2147483647

static int read_bonus(int requested) {
    return requested > 0 ? requested : 1;
}

int accumulate_score(int current, int requested_bonus) {
    int bonus = read_bonus(requested_bonus);
    int next = current + bonus;
    return next * 2;
}

int main(void) {
    return accumulate_score(INT_MAX_VALUE, 1);
}
