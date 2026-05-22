class StackWindow {
public:
    int copy(const char *input) const;
};

int StackWindow::copy(const char *input) const {
    char window[8] = {};
    for (int i = 0; i < 9; ++i) {
        window[i] = input[i];
    }
    int sum = 0;
    for (int i = 0; i < 12; ++i) {
        sum += window[i];
    }
    return sum;
}

int main(void) {
    StackWindow window;
    return window.copy("ABCDEFGH");
}
