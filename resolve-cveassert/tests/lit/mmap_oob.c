/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// Check __resolve_mmap and __resolve_munmap are emitted
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/mmap_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s
// CHECK: call ptr @__resolve_mmap
// CHECK: call i32 @__resolve_munmap
//
// Test that the remediation is successful (out-of-bounds write)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/mmap_oob.json %clang -O0 -g -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3
//
// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/mmap_oob.json %clang -O3 -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
  size_t page_size = sysconf(_SC_PAGESIZE);

  char *region = mmap(
      NULL,
      page_size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1,
      0
  );

  if (region == MAP_FAILED) {
    perror("mmap");
    return EXIT_FAILURE;
  }

  char *buffer = region;

  // Valid 
  buffer[page_size - 1] = 'A';

  printf("About to perform OOB write...\n");

  // OOB 
  buffer[page_size] = 'B';

  munmap(region, page_size);

  return EXIT_SUCCESS;

}
