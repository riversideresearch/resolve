extern "C" void *malloc(unsigned long size);
extern "C" void free(void *ptr);

class BufferOwner {
public:
    int bad_release(bool release_stack) const;
};

int BufferOwner::bad_release(bool release_stack) const {
    int stack_buffer[2];
    stack_buffer[0] = 1;
    stack_buffer[1] = 2;
    int *heap_buffer = static_cast<int *>(malloc(sizeof(int) * 2));
    if (!heap_buffer) {
        return 1;
    }
    heap_buffer[0] = 3;
    free(release_stack ? stack_buffer : heap_buffer);
    if (release_stack) {
        free(heap_buffer);
    }
    return stack_buffer[0];
}

int main(void) {
    BufferOwner owner;
    return owner.bad_release(true);
}
