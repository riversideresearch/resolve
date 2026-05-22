extern "C" void *malloc(unsigned long size);
extern "C" void free(void *ptr);

class ImageRow {
public:
    explicit ImageRow(int width);
    int paint(void) const;

private:
    int width_;
};

ImageRow::ImageRow(int width) : width_(width) {}

int ImageRow::paint(void) const {
    char *row = static_cast<char *>(malloc(static_cast<unsigned long>(width_)));
    if (!row) {
        return 1;
    }
    for (int i = 0; i <= width_ + 3; ++i) {
        row[i] = static_cast<char>('a' + (i % 3));
    }
    int result = row[width_ + 1];
    free(row);
    return result;
}

int main(void) {
    ImageRow row(6);
    return row.paint();
}
