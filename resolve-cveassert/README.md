<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# CVEAssert

CVEAssert is an LLVM compiler pass plugin that instruments programs by inserting
runtime checks into functions identified by a CVE description. It can optionally
be linked with the [`libresolve`](libresolve/README.md) runtime library to
enforce stack and heap bounds protections.

**Full documentation:** <https://riversideresearch.github.io/resolve/latest/components/resolve-cveassert/>
