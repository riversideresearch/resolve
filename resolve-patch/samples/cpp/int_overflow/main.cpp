#define INT_MAX_VALUE 2147483647

class CheckedCounter {
public:
    int bump(int first, int second) const;
};

int CheckedCounter::bump(int first, int second) const {
    int value = INT_MAX_VALUE;
    value = value + first;
    value = value + second;
    return value;
}

int main(void) {
    CheckedCounter counter;
    return counter.bump(1, 2);
}
