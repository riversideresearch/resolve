# Crash provenance

- **Program:** `greet` example built from `src/main.c`.
- **Build:** `clang -g -O0 -fsanitize=address src/main.c -o greet`
- **Reproducer:** run with an argument longer than 8 bytes:

  ```bash
  ./greet AAAAAAAAAAAAAAAAAAAAAAAAAAAA
  ```

- **Observed:** AddressSanitizer reports a stack-buffer-overflow and the process exits with code 1.
- **Evidence:** the full sanitizer report is in `asan.log`.
