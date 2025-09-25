
int div_zero_main(int argc, const char* argv[]) {
    int math = (int) (42.0 / (float)argc);

    return 42 % argc + math / argc;
}

int main(int argc, const char* argv[]) {
    // NOTE: call with 1 arg to trigger div by zero
    return div_zero_main(argc-2, argv);
}
