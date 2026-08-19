# Facts

Fact generation extracts structured information from [LLVM IR](https://llvm.org/docs/LangRef.html). Each fact describes a program node, property, or relationship.

The compiler pass writes a compact binary format. It compresses the data with zstd and embeds it in the ELF `.facts` section.

The [reach](reach.md) command reads facts from an ELF file or an extracted `.facts` file. The [reachability example](../examples/reachability.md) shows the complete workflow.
