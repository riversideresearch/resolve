<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# Resolve facts

Tools for creating and querying RESOLVE binary metadata, including the `reach` tool, which provides fast graph reachability for RESOLVE.

**Full documentation:**

- Facts: <https://riversideresearch.github.io/resolve/latest/components/facts/>
- `reach` tool: <https://riversideresearch.github.io/resolve/latest/components/reach/>

## Future Improvements

Strings are interned at an LLVM Module-level. If we were to intern strings across every module together, we would be able to get more space savings, but likely at the expense of more CPU-heavy assembly/decompression. It's also unclear if/how we could compress ELF strings inline.
