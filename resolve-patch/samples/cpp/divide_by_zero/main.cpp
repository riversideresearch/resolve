class Ratio {
public:
    explicit Ratio(int total);
    int normalize(int input) const;

private:
    int total_;
};

Ratio::Ratio(int total) : total_(total) {}

int Ratio::normalize(int input) const {
    int divisor = input - 2;
    return (total_ / divisor) + (total_ % divisor);
}

int main(void) {
    Ratio ratio(84);
    return ratio.normalize(2);
}
