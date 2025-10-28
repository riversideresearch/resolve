# RESOLVE (Reachability Enriched Software for Optimized Language-driven Vulnerability Exploration)

Project RESOLVE aims to be a framework that embeds and aids in exploit anticipation, triage, and remediation using integrated and enhanced software bill-of-material (eSBOM) metadata, runtime components,
and program analysis tools. The result is an enhanced toolchain where an analyst can easily and rapidly
identify, triage, and remediate potential vulnerabilities.

## Getting started 
To get started with the RESOLVE toolchain here is a high-level overview of each component.

### Compiler Passes
The RESOLVE toolchain modifies the Clang compiler with additional passes to perform program fact generation and remediation. The `AnnotateFunctions` pass collects function summaries (function arguments and their types, function return values and their types, and basic block numbers) for each function definition in the program. The `CVEAssert` pass applies sanitizers to an affect function in a program given a CVE description. At the time of writing the sanitizer capabilities we support cover memory and arithmetic vulnerabilities. The `DlsymHook` pass instruments dlysm function calls and `ObjHook` instruments C memory allocators. Furthermore, `EnhancedFacts` pass embeds program facts derived from the source code into custom ELF sections.     

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
Libresolve is a runtime library written in the Rust programming language.
The purpose of this library is to track object allocations and other kernel interactions. Furthermore,
the library can be configured to write runtime logs to a specific file descriptor. To learn more about libresolve and how it interacts with our suite of compiler passes check out this page <insert-link>.  

### Reach Tool
The reach tool is a fast graph tool to facilitate reachability analysis on a codebase. The development is factored into two parts, a library and executable that uses the library. This tool loads the fact files produced by the linker component and determines if there is a path from the program entry to the vulnerability. Upon finding the path, the tool will package the paths into a JSON object and write the path to a designated path (if given) or STDOUT file descriptor. Furthermore, we wrapped reach via python to create a wrapper called reach-wrapper.py which enables quicker access to the tool. For more information about the reach tool, check out this page <insert-link>.    


## BUILDING RESOLVE
```bash
cd resolve/
./install-deps  # Install necessary dependencies
make build      # Builds compiler passes, reach tool, and libresolve runtime library
```

## EXAMPLE
Here is an example of applying the RESOLVE toolchain to different applications.