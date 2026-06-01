#include "mimalloc.h"
#include "mimalloc/internal.h"
#include <stdint.h>
#include <stdio.h>

typedef struct {
  uint64_t page_id;
  size_t block_index;
  void *page_start;
} resolve_info_t;

resolve_info_t mi_resolve_ptr(void *p) {
  mi_page_t *page = _mi_ptr_page(p);

  resolve_info_t info;

  info.page_start = mi_page_start(p);
  info.page_id = (uint64_t)(uintptr_t)page;

  size_t block_size = page->block_size;
  uintptr_t offset = (uintptr_t)p - (uintptr_t)info.page_start;

  info.block_index = offset / block_size;

  return info;
}
