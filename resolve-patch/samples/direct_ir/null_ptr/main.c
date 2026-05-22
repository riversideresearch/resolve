static int *select_slot(int enabled, int *fallback) {
    return enabled ? fallback : 0;
}

int store_config(int enabled) {
    int local = 7;
    int *slot = select_slot(enabled, &local);
    *slot = 99;
    return local;
}

int main(void) {
    return store_config(0);
}
