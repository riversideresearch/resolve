class FlagEncoder {
public:
    unsigned int encode(unsigned int flags, int offset) const;
};

unsigned int FlagEncoder::encode(unsigned int flags, int offset) const {
    int amount = 32 + offset;
    return flags << amount;
}

int main(void) {
    FlagEncoder encoder;
    return static_cast<int>(encoder.encode(7u, 1));
}
