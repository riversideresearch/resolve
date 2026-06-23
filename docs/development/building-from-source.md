## Dependencies

Resolve has been tested on **Ubuntu 24.04.4 LTS**, but should work on other distributions that can provide the following packages:

- Clang 18
- LLVM 18
- Nightly Rust
- uv
- CMake
- build-essential
- make
- ninja-build
- clang-18
- clang-18-dev
- llvm-18
- llvm-18-dev
- git
- curl
- `codex`, `claude`, or `opencode`

## Building

```bash
git clone https://github.com/riversideresearch/resolve.git

cd resolve

# For normal install
make build
make install-local

# For KLEE
make build-with-klee
make install-with-klee
```

There are a handful of other targets for varying CMake build types. Investigate the `Makefile` in the repo root for more options.