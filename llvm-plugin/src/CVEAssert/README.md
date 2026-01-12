<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# CVEAssert
CVEAssert is an LLVM compiler pass that instruments source code
by applying a sanitizer to an affected function. CVEAssert takes a CVE description formatted using a json. 

# Types of Sanitizers
| Type | Sanitizer |
| --- | --- |
| Arithmetic | Divide by Zero|
| Arithmetic | Integer Overflow | 
| Memory | Heap OOB |
| Memory | Stack OOB |
| Memory | Null Pointer Deref |
| Other | Operation Masking | 

