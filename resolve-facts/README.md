<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# Resolve facts

Libraries for creating and querying RESOLVE binary metadata. The `libreach` library provides graph construction and path search for the `resolve reach` command.

**Full documentation:**

- Facts: <https://riversideresearch.github.io/resolve/latest/components/facts/>
- Reachability analysis: <https://riversideresearch.github.io/resolve/latest/components/reach/>

## Future Improvements

Strings are interned at an LLVM Module-level. If we were to intern strings across every module together, we would be able to get more space savings, but likely at the expense of more CPU-heavy assembly/decompression. It's also unclear if/how we could compress ELF strings inline.
