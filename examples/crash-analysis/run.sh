#!/usr/bin/env bash
set -euo pipefail

clang -g -O0 -fsanitize=address src/main.c -o greet
ASAN_OPTIONS=detect_leaks=0 ./greet AAAAAAAAAAAAAAAAAAAAAAAAAAAA > crash/asan.log 2>&1 || true

resolve crash-analysis claude -i crash -s src -o out --overwrite

echo "Vulnerability artifacts written to out/"
