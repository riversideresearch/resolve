extern void *malloc(unsigned long size);
extern void free(void *ptr);

static void release_candidate(int *ptr) {
    free(ptr);
}

int release_alias(int use_stack) {
    int stack_value = 5;
    int *heap_value = (int *)malloc(sizeof(int));
    if (!heap_value) {
        return 1;
    }
    *heap_value = 10;
    release_candidate(use_stack ? &stack_value : heap_value);
    if (use_stack) {
        free(heap_value);
    }
    return stack_value;
}

int main(void) {
    return release_alias(1);
}
