# Facts

Fact generation is a static program analysis technique that extracts structured information about a program from its source code or intermediate representation (i.e. LLVM-IR). A *fact* is a piece of information that describes some property of a program. Facts can be used to describe relationships between code and data. The `EnhancedFacts` pass plugin constructs program facts based on the program's control- and data-flow, and embeds these facts into custom ELF sections for downstream analysis.

These facts are compressed with zstd and stored inside a custom ELF section in the compiled binary called `.facts`. Reachability analysis can be performed by the [reach](reach.md) tool, which consumes these facts in its analysis. 

!!! note
    Developed for easy parsing and to encourage compatibility with third party tools, the facts format can consume quite a bit of storage and memory, particularly when uncompressed, due to being text-based. 
