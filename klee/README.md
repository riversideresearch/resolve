KLEE Symbolic Virtual Machine
=============================

# Directed KLEE for RESOLVE

TODO: description

## Setup

### Install deps

```bash
python -m pip install lit wllvm && \
sudo apt install ninja-build libncurses-dev libz3-dev zlib1g-dev libgoogle-perftools-dev libsqlite3-dev llvm-16-dev
```

### Install llvm-16 and clang-16

```bash
BASE=$HOME/klee_deps LLVM_VERSION=16 UCLIBC_VERSION=klee_uclibc_v1.4 Z3_VERSION=4.8.14 ENABLE_OPTIMIZED=1 ENABLE_DEBUG=0 DISABLE_ASSERTIONS=1 REQUIRES_RTTI=0 ENABLE_DOXYGEN=0 ./scripts/build/build.sh uclibc clang z3
```

### Build klee-uclibc 1.4 with our modifications (see section below for details)
```bash
cd klee-uclibc-160/ && \
./configure --make-llvm-lib --with-cc clang-16 --with-llvm-config llvm-config-16
make -j$(nproc)
```

### Build KLEE

```bash
mkdir build && cd build && \
cmake -DLLVM_DIR=/usr/lib/llvm-16 -DCMAKE_BUILD_TYPE=Release -DENABLE_SOLVER_STP=OFF -DENABLE_SOLVER_Z3=ON -DENABLE_POSIX_RUNTIME=ON -DKLEE_UCLIBC_PATH=../klee-uclibc-160 -DENABLE_UNIT_TESTS=OFF -DENABLE_KLEE_ASSERTS=OFF -DKLEE_RUNTIME_BUILD_TYPE=Release .. && \
make -j$(nproc)
```

mkdir build && cd build && \
cmake -DLLVM_DIR=$HOME/klee_deps/llvm-160-build_O_ND_NA -DCMAKE_BUILD_TYPE=Debug -DENABLE_SOLVER_STP=OFF -DENABLE_SOLVER_Z3=ON -DENABLE_POSIX_RUNTIME=ON -DKLEE_UCLIBC_PATH=../klee-uclibc-160 -DENABLE_UNIT_TESTS=OFF -DENABLE_KLEE_ASSERTS=OFF -DKLEE_RUNTIME_BUILD_TYPE=Debug -DLLVMCC=/usr/bin/clang-16 .. && \
make -j$(nproc)

### Run KLEE

Example:

```bash
build/bin/klee --only-output-states-covering-new --exit-on-error-type=Ptr --libc=uclibc -posix-runtime prog.bc arg1 arg2
```

In VM for some reason I needed to create a symbolic link to the `asm`
directory for x86_64-linux-gnu:
```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```
The directory to link to was found by running:
```bash
find /usr/include -name "param.h" | grep asm
```

## Modifications in klee-uclibc

We add `__isoc99_sscanf` for the json_parser program.

At `klee-uclibc-160/include/stdio.h:400`, added:
```
extern int __isoc99_sscanf (__const char *__restrict __s,
		   __const char *__restrict __format, ...) __THROW;
```

At `klee-uclibc-160/libc/stdio/_scanf.c:221`, added:
```
libc_hidden_proto(__isoc99_sscanf)
int __isoc99_sscanf(const char * __restrict str, const char * __restrict format, ...)
{
  va_list arg;
  int rv;

  va_start(arg, format);
  rv = vsscanf(str, format, arg);
  va_end(arg);

  return rv;
}
libc_hidden_def(__isoc99_sscanf)
```

# KLEE

`KLEE` is a symbolic virtual machine built on top of the LLVM compiler
infrastructure. Currently, there are two primary components:

  1. The core symbolic virtual machine engine; this is responsible for
     executing LLVM bitcode modules with support for symbolic
     values. This is comprised of the code in lib/.

  2. A POSIX/Linux emulation layer oriented towards supporting uClibc,
     with additional support for making parts of the operating system
     environment symbolic.

Additionally, there is a simple library for replaying computed inputs
on native code (for closed programs). There is also a more complicated
infrastructure for replaying the inputs generated for the POSIX/Linux
emulation layer, which handles running native programs in an
environment that matches a computed test input, including setting up
files, pipes, environment variables, and passing command line
arguments.

For further information, see the [webpage](http://klee.github.io/).
