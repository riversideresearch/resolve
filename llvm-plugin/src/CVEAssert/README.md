<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# CVEAssert
CVEAssert is an LLVM compiler pass that instruments source code
by applying a sanitizer to an affected function. CVEAssert takes a CVE description formatted using a json. CVEAssert instruments programs that exhibit arithmetic and memory vulnerabilities. 

## Types of Sanitizers
| Type | Sanitizer |
| --- | --- |
| Arithmetic | Divide by Zero|
| Arithmetic | Integer Overflow | 
| Memory | Heap OOB |
| Memory | Stack OOB |
| Memory | Null Pointer Deref |
| Other | Operation Masking | 

## Directory Structure
```bash
.
├── arith_san.cpp     - Source code for arithmetic sanitizers (i.e. divide by zero, integer overflow)
├── bounds_check.cpp  - Source code for OOB-access memory sanitizers 
├── CVEAssert.cpp     - Driver code 
├── helpers.cpp       - Helper functions 
├── null_ptr.cpp      - Source code for null pointer sanitizers
├── undesirableop.cpp - Source code for operation masking sanitizer
├── Vulnerability.hpp - Source code for internal data structure to parse CVE description
└── Worklist.hpp      - Source code for internal data structure
```
## Supported Sanitizers 
| Sanitizer | Behavior | 
| --- | --- |
| Divide by Zero | Collects division and remainder operation in vulnerable function. Inserts checks before operations to check if divisors are zero. |
| Integer Overflow | Collects arithmetic instructions in vulnerable function. Checks for the presence of *nsw* and *nuw* flags and inserts arithmetic overflow checking instructions. |
| Heap/Stack OOB | Collects load/store and GEP (getelementptr) instructions in the vulnerable function. Replaces load/store and GEPs with instrumented versions. |
| Null Pointer Dereference | Collects load/store operations in the vulnerable function. Replaces load/store operations with instrumented versions. |
| Operation Masking | Collects function calls in vulnerable function that are "undesirable". Replaces old calls with calls to a sanitized version of the undesirable function that returns the value of the first argument. | 

 Testing LLVM-IR rendering
```llvm
define dso_local i32 @square(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  %3 = load i32, ptr %2, align 4
  %4 = load i32, ptr %2, align 4
  %5 = mul nsw i32 %3, %4
  ret i32 %5
}
```
