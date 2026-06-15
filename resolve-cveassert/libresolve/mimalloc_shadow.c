#include "mimalloc.h"
#include "mimalloc/internal.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

extern void* __resolve_malloc(size_t);
extern void __resolve_free(void*);


typedef struct {
  void *base;
  void *limit;
  size_t block_size;
  size_t block_index;
} bounds_info_t;


bounds_info_t mi_resolve_ptr(void* p) {
  mi_page_t *page = _mi_ptr_page(p);
  
  const size_t block_size = page->block_size;

  uintptr_t page_start = (uintptr_t)page->page_start;
  uintptr_t ptr = (uintptr_t)p;

  size_t block_index = (ptr - page_start) / block_size; 
  uintptr_t base_addr = page_start + block_index * block_size;

  bounds_info_t bounds;
  bounds.base = (void*)base_addr;
  bounds.limit = (void*)(base_addr + block_size);
  bounds.block_size = block_size;
  bounds.block_index = block_index;
  return bounds;
}

bool mi_is_heap_owned(const void* p) {
  return mi_is_in_heap_region(p);
}

int __vasprintf(char **strp, const char *fmt, va_list ap)
{
  va_list ap_copy;
  va_copy(ap_copy, ap);

  int len = vsnprintf(NULL, 0, fmt, ap_copy);
  va_end(ap_copy);

  if (len < 0) { 
    // to match glibc behavior
    *strp = NULL;
    return -1; 
  }

  char *buf = __resolve_malloc((size_t)len);
  if (!buf) { return -1; }

  va_copy(ap_copy, ap);

  int written = vsnprintf(buf, (size_t)len + 1, fmt, ap_copy);

  va_end(ap_copy);

  if (written < 0) {
    __resolve_free(buf);
    return -1;
  }

  *strp = buf;
  return written;
}
