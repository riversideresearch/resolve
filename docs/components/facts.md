# Facts

Facts are information about a program, extracted from [LLVM IR](https://llvm.org/docs/LangRef.html) at compile-time. Each fact describes a program node, property, or relationship. The collection of facts can form a Control Flow Graph, though they carry additional metadata beyond just that.

[resolvecc](resolve-cc.md) will produce and embed facts into a `.facts` section inside the compiled ELF in a compact binary format, typically compressed with zstd.

The [reach](reach.md) command consumes these facts from an ELF file, shared objcet, or an extracted `.facts` file. The [reachability example](../examples/reachability.md) shows a complete end-to-end example of this.

## Binary Format Specification

The binary format is typically compressed with zstd when it is attached to compiled objects. A zstd frame can be identified by the leading bytes: `28 B5 2F FD`.

For definitive structure, consult the [Rust schema](https://github.com/riversideresearch/resolve/tree/main/resolve-facts/rs/src/schema.rs).

The uncompressed facts stream has no top-level header. It contains one or more modules in sequence:

```text
Facts stream
├── ModuleHeader (16 bytes)
│   ├── version:         u32
│   ├── node_count:      u32
│   ├── edge_count:      u32
│   └── string_pool_len: u32
├── Node[node_count] (32 bytes each)
│   ├── meta:          u32 (multiple bitmasks)
│   ├── idx:           u32
│   ├── name:          u32 (string offset)
│   ├── opcode:        u32 (string offset)
│   ├── source_line:   u32
│   ├── source_col:    u32
│   ├── source_file:   u32 (string offset)
│   └── function_type: u32 (string offset)
├── Edge[edge_count] (12 bytes each)
│   ├── src:   u32 (NodeID)
│   ├── dst:   u32 (NodeID)
│   └── kinds: u32 (bitmask)
├── String pool (string_pool_len bytes)
│   └── repeated [byte length: u32][UTF-8 bytes ...]
└── Next module, if present
```

A node ID is its index in the node array of its module. The `meta` field stores the node type, property flags, linkage, and call type.

The `kinds` field is a bit set. One source and destination pair can have multiple relationships, such as `Calls`, `Contains`, or `ControlFlowTo`.

The string pool has four-byte alignment. The writer adds zero padding after the final string when the pool requires it.
