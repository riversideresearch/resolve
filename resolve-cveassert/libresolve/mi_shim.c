// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

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
  size_t size;
} mi_alloc_bounds_t;


mi_alloc_bounds_t mi_get_alloc_bounds(void* p) {
  mi_alloc_bounds_t bounds;
  mi_alloc_bounds_t empty = { .base = (void*) -1, .limit = (void*)-1, .size = 0 };

  // Check if ptr is owned by mimalloc
  if (!mi_is_in_heap_region(p)) {
    return empty;
  }

  // Recover the page information for the pointer.
  mi_page_t *page = _mi_ptr_page(p);

  if (page == NULL) {
    return empty;
  }
  
  // _mi_page_ptr_unalign recovers the corresponding 
  // block for base and interior pointers 
  mi_block_t *base = _mi_page_ptr_unalign(page, p);
  if (!base) { return empty; }

  bounds.base = (void *)base;
  bounds.size = mi_usable_size(base);
  bounds.limit = (void *)base + bounds.size;
  return bounds;
}

bool mi_is_heap_owned(const void* p) {
  return _mi_ptr_page(p) != NULL;
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

  char *buf = __resolve_malloc((size_t)len + 1);
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

/* debugging function to help check if a pointer the 
  base address or an offset into the block 
*/
bool mi_is_block_start(void *p) {
  if (p == NULL) { return false; }
  
  // Recover page information
  mi_page_t *page = _mi_ptr_page(p);

  if (page == NULL) { return false; }

  // Compute the block index
  const size_t block_size = page->block_size;
  uintptr_t page_start = (uintptr_t)page->page_start;
  size_t block_index = ((uintptr_t)p - page_start) / block_size;

  // Compute the canonical base.
  uintptr_t base = page_start + block_index * block_size;
  
  // Compare to pointer
  return base == (uintptr_t)p;
}

