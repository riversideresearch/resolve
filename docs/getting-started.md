<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# `resolve`

`resolve` is an LLVM-based software security tool designed to anticipate, triage and remediate CVEs. It combines binary metadata based on enhanced software bills-of-material, or eSBOMs, with runtime components and program analysis tools that together speed up the process of identifying and remediating bugs.

## Getting started 
`resolve` consists of a number of components. See below for high-level descriptions.

### Compiler Pass Plugins
`resolve` modifies the Clang compiler by dynamically loading pass plugins to perform program fact generation and remediation.

Fact generation is a static program analysis technique that extracts structured information about a program from its source code or intermediate representation (i.e. LLVM-IR). A *fact* is a piece of information that describes some property of a program. Facts can be used to describe relationships between code and data. The `EnhancedFacts` pass plugin constructs program facts based on the program's control- and data-flow, and embeds these facts into custom ELF sections for downstream analysis.

The `AnnotateFunctions` pass plugin inserts inline runtime monitors to collect function activation metadata during offline analysis. The inserted inline monitor links against `libresolve`, a runtime library that records activation summaries to files.

Given a CVE description in structured `.json`, the `CVEAssert` pass plugin inserts runtime checks to an affected function. `CVEAssert` currently supports a number of memory and arithmetic vulnerability classes.

`DlsymHook` instruments calls to `dlysm`. `ObjHook` instruments C memory allocators. These pass plugins must be linked against `libresolve`.   

| LLVM Pass | Behavior |
| --- | --- |
| `AnnotateFunctions` | Insert code to record function activations |
| `CVEAssert` | Given `.json` CVE description, insert runtime checks into affected function | 
| `DlsymHook` | Instrument 'dlsym' function calls |
| `EnhancedFacts` | Embed facts derived from program source code into custom ELF sections |
| `ObjHook` | Instrument C memory allocators |
