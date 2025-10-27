# RESOLVE (Reachability Enriched Software for Optimized Language-driven Vulnerability Exploration)

Project RESOLVE aims to be a framework that embeds and aids in exploit anticipation, triage, and remediation using integrated and enhanced software bill-of-material (eSBOM) metadata, runtime components,
and program analysis tools. The result is an enhanced toolchain where an analyst can easily and rapidly
identify, triage, and remediate potential vulnerabilities.

## Getting started 
There are several components to the RESOLVE toolchain.

### COMPILER PASSES


### LINKER
The linker component handles extracting facts from the corresponding ELF binary sections. Those sections are then written to files to be consumed by the reach tool for reachability analysis.  

### LIBRESOLVE
Libresolve is a runtime library written in the Rust programming language.
The purpose of this library is to track object allocations and other kernel interactions. Furthermore,
the library can be configured to write runtime logs to a specific file descriptor. To learn more about libresolve and how it interacts with our suite of compiler passes check out this page <insert-link>.  

### REACH TOOL
The reach tool is a fast graph tool to facilitate reachability analysis on a codebase. The development is factored into two parts, a library and executable that uses the library. This tool loads the fact files produced by the linker component and determines if there is a path from the program entry to the vulnerability. Upon finding the path, the tool will package the paths into a JSON object and write the path to a designated path (if given) or STDOUT file descriptor. Furthermore, we wrapped reach via python to create a wrapper called reach-wrapper.py which enables quicker access to the tool. For more information about the reach tool, check out this page <insert-link>.    


## BUILDING RESOLVE
```bash
cd resolve/
./install-deps  # Install necessary dependencies
make build      # Builds compiler passes, reach tool, and LibRESOLVE runtime library
```

## EXAMPLE
Here is an example of applying the RESOLVE toolchain to different applications.