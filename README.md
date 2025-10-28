# RESOLVE (Reachability Enriched Software for Optimized Language-driven Vulnerability Exploration)

Project RESOLVE aims to be a framework that embeds and aids in exploit anticipation, triage, and remediation using integrated and enhanced software bill-of-material (eSBOM) metadata, runtime components,
and program analysis tools. The result is an enhanced toolchain where an analyst can easily and rapidly
identify, triage, and remediate potential vulnerabilities.

## Getting started 
To get started with the RESOLVE toolchain here is a high-level overview of each component.

### Compiler Passes
The RESOLVE toolchain modifies the Clang compiler with additional passes to perform program fact generation and remediation.

Program fact generation is a static program analysis technique that extracts structured information about a binary from its source code or intermediate representation (i.e. LLVM-IR). A *fact* is a piece of information that describes some property of a program. Facts can be used to describe realtionships between code and data. The `EnhancedFacts` pass constructs program facts based on the program's control and dataflow, and embeds these facts into custom ELF sections for downstream analysis.

The `AnnotateFunctions` pass collects function summaries for each function definition in the program. Function summaries are defined as metadata that contains a function's arguments, return values This pass can be linked against Libresolve, a runtime library to record these summaries in a given file location.

The `CVEAssert` pass applies sanitizers to an affect function in a program given a CVE description. At the time of writing, the sanitizer capabilities we support cover memory and arithmetic vulnerability classes.

The `DlsymHook` pass instruments `dlysm` function calls and `ObjHook` instruments C memory allocators. These passes can also be linked against libresolve to enable logging `dlsym` calls and allocator calls, which can useful in tracing calls in the kernel to identify potential vulnerabilities.   

| LLVM Pass | Behavior |
| --- | --- |
| `AnnotateFunctions` | Collect function summaries for each function definition |
| `CVEAssert` | Applies sanitizer to affected function given a CVE description | 
| `DlsymHook` | Instrument 'dlsym' function calls |
| `EnhancedFacts` | Embed facts derived from program source code into custom ELF sections |
| `ObjHook` | Instrument C memory allocators |


### Linker
The linker component handles extracting facts from the corresponding ELF binary sections embedded by the `EnhancedFacts` compiler pass. Those sections are then written to files to be consumed by the reach tool for reachability analysis.  

### Libresolve
Libresolve is a runtime library written in Rust.
The purpose of this library is to track object allocations and monitor kernel interactions during program execution. The library can be configured to write runtime logs to a specified file descriptor for further analysis.

To learn more about Libresolve and its integration with our suite of compiler passes, see the [Libresolve documentation](https://github.com/riversideresearch/resolve/tree/main/libresolve).  

### Reach Tool
The reach tool is a fast graph-based utility designated to facilitate reachability on a codebase. Its implementation is divided into two components: a core library and an executable that uses the library.

Reach consumes the fact files produced by the linker component and determines whether a path exists from the program entry point to a specified vulnerability. When a path is found, Reach packages the results into a JSON object and writes them either to a user specified output path or to STDOUT by default. 

A Python wrapper, `reach-wrapper.py`, provides a convenient command line interface to interact with the reach tool. For more information about the reach tool, see the [documentation page](https://github.com/riversideresearch/resolve/tree/main/reach).


## BUILDING RESOLVE
```bash
cd resolve/
./install-deps  # Install necessary dependencies
make build      # Builds compiler passes, reach tool, and libresolve runtime library
```

## EXAMPLE
Here is an example of applying the RESOLVE toolchain to different applications.