<!--
  Copyright (c) 2025 Riverside Research.
  See LICENSE.txt in the repo root for licensing information.
-->

# LIBRESOLVE

Libresolve is a runtime library that tracks object allocations and other kernel interactions.
It is primarily designed for the **EBOSS RESOLVE toolchain**.

## Build
```bash
git clone https://gitlab.ebossproject.com/riverside/libresolve.git
cd libresolve/
cargo build             # Debug build (default)
```

## Usage
1. Build the rust library in `libresolve/`.
2. Link the library with the binary using linker options.
3. Set ENV variables accordingly.
4. Execute the binary. 


## Directory Structure
```bash
.
├── Cargo.lock
├── Cargo.toml
├── README.md
└── src                     - libresolve source code 
    ├── buffer_writer.rs    - minimal formatting into byte buffers
    ├── lib.rs              - allocator and runtime logging interface 
    └── shadowobjs.rs       - Shadow object tracking implementation 
```

## Environment variables
Libresolve uses environment variables to control where the runtime logs are written:
- `RESOLVE_DLSYM_LOG`       - Path to the `dlsym` log file.
- `RESOLVE_RUNTIME_LOG`     - Path to the main runtime log file. 
- `RESOLVE_RUNTIME_ERR_LOG` - Path to the runtime error log file.

Each log file automatically appends the process ID before the extension. 
For example, setting:
```bash
export RESOLVE_RUNTIME_LOG=./resolve_log.out
```

After linking and running the resulting file will have this format.
```bash
./resolve_log_<pid>.out
```

## LLVM Passes
Libresolve is designed to used with the LLVM passes within the EBOSS RESOLVE toolchain.
These are the passes that can be used with Libresolve.
- `AnnotateFunctions`
- `CVEAssert`
- `DlsymHook`
- `ObjHook`

| LLVM Passes | Intended behavior with Libresolve | 
| --- | --- |
| `AnnotateFunctions` | Logs function summaries in `resolve_log_<pid>.out` |
| `CVEAssert` | Logs irregular memory accesses in `resolve_err_log_<pid>.out` |
| `DlsymHook` | Logs calls to `dlsym` in `resolve_dlsym.json` | 
| `ObjHook` | Logs memory allocators in `resolve_log_<pid>.out` | 

# AnnotateFunctions
The `AnnotateFunctions` pass collects function summaries for each function definition. Function summaries contain a function's runtime arguments and their types, and their return values and their types. When Libresolve is used with `AnnotateFunctions`, the resulting behavior is the `resolve_log_<pid>.out` is produced containing the function summary runtime information.

# CVEAssert
The `CVEAssert` pass applies a sanitizer to an affected function when a CVE description is given. The CVE description is formatted using a json and is passed to `CVEAssert` via an env variable called `RESOLVE_LABEL_CVE`. When Libresolve is used with `CVEAssert` the resulting behavior is Libresolve performing bounds checking at runtime. If an OOB (Out-Of-Bounds) access occurs then Libresolve will open and write to `resolve_err_log_<pid>.out` to log the irregular memory access.

# DlsymHook
The `DlsymHook` pass instruments `dlsym` function calls and wrapping them with the `resolve_` prefix. When Libresolve is used with `DlsymHook`, the resulting behavior the file, `resolve_dlsym.json` is produced which contains information about which dynamically linked libraries are used in a program. 

# ObjHook
The `ObjHook` pass instruments memory allocators by wrapping them with the `resolve_` prefix. When Libresolve is used with `ObjHook`, the resulting behavior is Libresolve creating shadow objects per each memory allocation logged and logs each allocation in `resolve_log_<pid>.out`.

The ObjHook pass supports these memory allocations currently.
- `malloc`
- `calloc`
- `free`
- `realloc`
- `strdup`
- `strndup`

## License
[MIT](./LICENSE)