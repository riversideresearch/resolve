# Resolve Patch Samples

This directory contains isolated C and C++ patch/recompilation samples for the Resolve/CVEAssert sanitizers. Each sample is a standalone tiny project with:

- `main.c` or `main.cpp`
- `vulnerabilities.json`
- `CMakeLists.txt`
- a generated `build/` directory after running the sample

## Covered Sanitizers

- Divide by zero
- Integer overflow
- Heap out-of-bounds
- Stack out-of-bounds
- Null pointer dereference
- Free of non-heap memory
- Bit shift
- Operation masking

## Running

Run every sample:

```bash
./build.sh
```

Run one sample:

```bash
./build.sh c/null_ptr
./build.sh cpp/heap_oob
```

For each selected sample, the runner:

1. Configures and builds `main` with `resolvecc` or `resolvecxx`.
2. Runs the original binary, allowing expected failures.
3. Disassembles it with `llvm-mctoll` into `main-dis.ll`.
4. Applies `resolve-patch.ll` with `patcher.py`.
5. Recompiles `main-patched.ll`.
6. Runs the patched binary.

<small>(samples were produced by Codex 5.5 High, then hand-edited and verified)</small>
