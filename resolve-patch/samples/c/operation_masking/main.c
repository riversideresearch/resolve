int dangerous_select(int untrusted, int fallback) {
    return untrusted < 0 ? fallback : untrusted;
}

int filter_untrusted_call(int external_value) {
    int sanitized = dangerous_select(external_value, 4);
    return sanitized * 3;
}

int main(void) {
    return filter_untrusted_call(-10);
}
