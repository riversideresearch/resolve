class Widget {
public:
    int refresh(bool allocate) const;
};

int Widget::refresh(bool allocate) const {
    int local = 3;
    int *value = allocate ? &local : 0;
    *value = 11;
    return local;
}

int main(void) {
    Widget widget;
    return widget.refresh(false);
}
