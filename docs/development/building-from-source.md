## Dependencies

**RESOLVE** has been tested on **Ubuntu 24.04.4 LTS**, but should work on other distributions that can provide the following packages:

- Nightly Rust
- cbindgen (`cargo install cbindgen --version 0.29.0 --locked`)
- uv
- CMake
- build-essential
- ninja-build
- clang-18
- clang-18-dev
- llvm-18
- llvm-18-dev
- git
- curl
- `codex`, `claude`, or `opencode`

## Building

To create a loose file tree version of **RESOLVE** suitable for local development, you can do the following:

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

## Building A Release

To build a release tar file locally, you can run:

```bash
make release
```

This can then be installed with `sudo tar -C / -xzf {TAR FILE}`, which extracts it into `/opt/resolve`.
