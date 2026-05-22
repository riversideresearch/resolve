extern "C" int mask_candidate(int untrusted, int fallback) {
    return untrusted < 0 ? fallback : untrusted;
}

class Policy {
public:
    int apply(int external_value) const;
};

int Policy::apply(int external_value) const {
    int selected = mask_candidate(external_value, 6);
    return selected + 10;
}

int main(void) {
    Policy policy;
    return policy.apply(-12);
}
