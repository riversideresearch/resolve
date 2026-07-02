# resolvecc

The `resolve-cc` source folder contains the `resolvecc` compiler wrapper and scripts for extracting [facts](facts.md) from the ELF binary sections embedded by the `EnhancedFacts` compiler pass plugin. Those sections are then written to files to be consumed by the [`reach`](reach.md) tool for reachability analysis. The `resolve` ELF sections in which metadata is embedded are compatible with standard linkers; a custom linker is not required for linking `resolve`-generated binaries.

!!! tip
    `resolvecc` is exercised end-to-end in the [reachability example](../examples/reachability.md) (fact generation) and the [remediation example](../examples/remediation.md) (compile-time fixes).

If you have a valid clang-18 install, running:

```bash
resolvecc --help
```

Will present you with the following usage instructions:

```txt
resolvecc — clang wrapper with RESOLVE plugins 

USAGE:
    resolvecc [options] file...

DESCRIPTION:
    resolvecc wraps clang and automatically:

      • Loads the CVEAssert LLVM pass plugin
      • Loads the ResolveFactsPlugin LLVM pass plugin
      • Links against libresolve at link time

WRAPPER OPTIONS:
    -fcve-assert <file>
        Path to CVE assertion configuration JSON file.

    -fno-resolve
        Does not load fact generation plugin.
    
    -lresolve 
        Links against libresolve at link time. 

    -h, --help
        Show this help message.

All other options are forwarded directly to clang.

EXAMPLES:
    resolvecc -fcve-assert vuln.json test.c
    resolvecc -fcve-assert vuln.json -lresolve -O2 -g test.c
    resolvecc -fno-resolve test.c 
    resolvecc -c test.c
```

## Additional Passes

The `AnnotateFunctions` pass plugin inserts inline runtime monitors to collect function activation metadata during offline analysis. The inserted inline monitor links against `libresolve`, a runtime library that records activation summaries to files.

`DlsymHook` instruments calls to `dlysm`. `ObjHook` instruments C memory allocators. These pass plugins must be linked against `libresolve`.   

| LLVM Pass | Behavior |
| --- | --- |
| `AnnotateFunctions` | Insert code to record function activations |
| [`CVEAssert`](resolve-cveassert.md) | Given `.json` CVE description, insert runtime checks into affected function | 
| `DlsymHook` | Instrument 'dlsym' function calls |
| `EnhancedFacts` | Embed facts derived from program source code into custom ELF sections |
| `ObjHook` | Instrument C memory allocators |
