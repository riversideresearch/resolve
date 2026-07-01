void do_npd(void *ptr) {
    *(int *)ptr = 0;
}

int main(void) {
    do_npd(0x0);
    return 0;
}
