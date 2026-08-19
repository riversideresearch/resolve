/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// Check the registration constructor is emitted and wired into llvm.global_ctors
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/multiple_globals_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s
//
// Test that the remediation is successful (out-of-bounds read and write)
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/multiple_globals_oob.json %clang -O0 -g -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3
//
// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/multiple_globals_oob.json %clang -O3 -fpass-plugin=%plugin \
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

#include <stdio.h>
#include <stdint.h>

/* Lots of global variables */
int g0 = 0;
int g1 = 1;
int g2 = 2;
int g3 = 3;
int g4 = 4;
int g5 = 5;
int g6 = 6;
int g7 = 7;
int g8 = 8;
int g9 = 9;

char banner[64] = "RESOLVE Global Bounds Test";

int globals0[10];
int globals1[10];
int globals2[10];
int globals3[10];

long counter0 = 100;
long counter1 = 200;
long counter2 = 300;
long counter3 = 400;
long counter4 = 500;

volatile uint64_t flags[64];

/* Target global */
int target[8] = {
  10, 20, 30, 40,
  50, 60, 70, 80
};

int main(int argc, char **argv) {
  for (int i = 0; i < 10; ++i) {
    globals0[i] = i;
    globals1[i] = i + 100;
    globals2[i] = i + 200;
    globals3[i] = i + 300;
  }

  printf("target[0] = %d\n", target[0]);

  /* Out-of-bounds read */
  int value = target[20];

  printf("OOB read: %d\n", value);

  /* Out-of-bounds write */
  target[24] = 12345;

  printf("Done\n");

  return 0;
}

