# `resolve`

`resolve` is an LLVM-based software security tool designed to anticipate, triage and remediate CVEs. It combines binary metadata based on enhanced software bills-of-material, or eSBOMs, with runtime components and program analysis tools that together speed up the process of identifying and remediating bugs.

## Getting started 
`resolve` consists of a number of components. See below for high-level descriptions.

### Compiler Passes
`resolve` modifies the Clang compiler with additional passes to perform program fact generation and remediation.

Fact generation is a static program analysis that extracts structured information about a program from its source code or intermediate representation (i.e. LLVM-IR). A *fact* is a piece of information that describes some property of a program. Facts can be used to describe relationships between code and data. The `EnhancedFacts` pass constructs program facts based on the program's control- and data-flow, and embeds these facts into custom ELF sections for downstream analysis.

The `AnnotateFunctions` pass inserts inline runtime monitors to collect function activation metadata during offline analysis. The inserted inline monitor links against `libresolve`, a runtime library that records activation summaries to files.

Given a CVE description in structured `.json`, the `CVEAssert` pass applies sanitizers to an affected function. `CVEAssert` currently supports a number of memory and arithmetic vulnerability classes (see TODO for details).

`DlsymHook` instruments calls to `dlysm`. `ObjHook` instruments C memory allocators. These passes must also be linked against `libresolve`.   

| LLVM Pass | Behavior |
| --- | --- |
| `AnnotateFunctions` | Insert code to record function activations |
| `CVEAssert` | Given `.json` CVE description, apply sanitizer to affected function | 
| `DlsymHook` | Instrument 'dlsym' function calls |
| `EnhancedFacts` | Embed facts derived from program source code into custom ELF sections |
| `ObjHook` | Instrument C memory allocators |


### Linker
`linker` includes scripts for extracting facts from the ELF binary sections embedded by the `EnhancedFacts` compiler pass. Those sections are then written to files to be consumed by the `reach` tool for reachability analysis. The `resolve` ELF sections in which metadata is embedded are compatible with standard linkers; a custom linker is not required for linking `resolve`-generated binaries. 

### `libresolve`
`libresolve` is a runtime library for tracking object allocations. The library can be configured to write runtime logs to a specified file descriptor for further analysis.

To learn more about `libresolve` and its integration with our suite of compiler passes, see the [`libresolve` documentation](https://github.com/riversideresearch/resolve/tree/main/libresolve).  

### `reach`
`reach` performs static reachability queries on `resolve` program metadata. It consumes the fact files extracted from binaries by `linker` and determines whether a path exists from the program entry point to a specified vulnerability. When a path is found, `reach` packages the results into a `.json` object and writes them either to a user-specified path or to `stdout` by default. 

A Python wrapper, `reach-wrapper.py`, provides a convenient command-line interface to interact with `reach`. For more information about `reach`, see the [`reach` documentation](https://github.com/riversideresearch/resolve/tree/main/reach).


## BUILDING `resolve`
```bash
cd resolve/
chmod u+x scripts/install-deps.sh
./scripts/install-deps              # Install necessary dependencies
make build                          # Builds compiler passes, reach tool, and libresolve runtime library
make test                           # Runs test suite
```

## EXAMPLE
TODO
