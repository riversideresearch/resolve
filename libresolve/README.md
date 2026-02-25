<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# LIBRESOLVE

Libresolve is a runtime library that tracks object allocations using shadow memory objects.
It is primarily designed for the **RESOLVE toolchain**.

## Build
```bash
git clone https://github.com/riversideresearch/resolve.git
cd libresolve/
cargo build --release            # Release build
```

## Usage
1. Build the rust library in `libresolve/`.
2. Link the library with the binary using linker options.
3. Execute the binary with `RUSTLOG=info`.

## Directory Structure
```bash
.
└── src
    ├── lib.rs        - File operations 
    ├── remediate.rs  - Runtime instrumentation 
    ├── shadowobjs.rs - Shadow object implementation 
    └── trace.rs      - Function prototypes for recording function activations  
```

## Environment variables
Libresolve uses environment variables to control where the runtime logs are written:
- `RESOLVE_DLSYM_LOG_DIR`
- `RESOLVE_RUNTIME_LOG_DIR`

Both environment variables expect a file path as input. If the file path has not been created then
libresolve will create the directories. If a file path is not set then libresolve 
will create the file in the same directory as the binary. 
Each log file automatically appends the process ID before the extension. 

>[!NOTE]
Both environment variables expect a file path as input. If the file path
has not been created then libresolve will attempt to create the necessary parent directories. 
If libresolve fails to create the necessary parent directories due to permission issues, an error is thrown and libresolve 
will panic.


## LLVM Passes
Libresolve is designed to used with the LLVM passes within the RESOLVE toolchain.

| LLVM Passes | Behavior with Libresolve | 
| --- | --- |
| `AnnotateFunctions` | Logs function summaries in `resolve_log_<pid>.out` |
| `CVEAssert` | Logs irregular memory accesses in `resolve_log_<pid>.out` |
| `DlsymHook` | Logs calls to `dlsym` in `resolve_dlsym.json` | 

# AnnotateFunctions
`AnnotateFunctions` collects function summaries for each function definition. Function summaries contain a function's runtime arguments and their types, and their return values and their types. 

When the instrumented function is linked with libresolve, it records the function summaries of all function definitions in the C/C++ project in `resolve_log_<pid>out`. Furthermore it records basic block transitions to be used in offline analysis.

# CVEAssert
`CVEAssert` inserts runtime checks into specified vulnerable functions in a C/C++ project based
on a supplied CVE description. The CVE description is encoded as a JSON.

When the instrumented program is linked with libresolve, it tracks stack and heap allocations using shadow metadata. If an invalid or security-relevant memory access occurs, libresolve records the event in `resolve_log_<pid>.out`.

# DlsymHook
The `DlsymHook` pass instruments calls to `dlsym` by wrapping them with the `resolve_` prefix. When libresolve is linked with `DlsymHook`, the runtime opens `resolve_dlsym.json` and records each dynamically resolved symbol along with its corresponding library.  