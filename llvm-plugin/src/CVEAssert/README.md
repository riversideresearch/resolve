<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for details.
-->

# CVEAssert
CVEAssert is an LLVM compiler pass that instruments programs 
by inserting runtime checks into functions identified as vulnerable.
It consumes a CVE description encoded in JSON, which is parsed into
an internal representation containing the target file, function,
weakness identifier, and remediation strategy. Based on this
description, CVEAssert selects and applies the appropriate sanitizer
to each affected function. CVEAssert can optionally be linked with
the [`libresolve`](/libresolve/README.md) runtime library to enforce stack and heap bounds. The pass is executed early in the compilation pipeline to allow LLVM's optimization framework to optimize the injected instrumentation. 

## Architecture Diagram
![CVEAssert pipeline](cveassert_pipeline.png)

## Types of Sanitizers
| Type | Sanitizer |
| --- | --- |
| Arithmetic | Divide by Zero|
| Arithmetic | Integer Overflow | 
| Memory | Heap OOB |
| Memory | Stack OOB |
| Memory | Free Nonheap | 
| Memory | Null Pointer Deref |
| Other | Operation Masking | 

## Directory Structure
```bash
.
├── arith_san.cpp     - Source code for arithmetic sanitizers (i.e. divide by zero, integer overflow)
├── bounds_check.cpp  - Source code for oob memory sanitizers 
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
| Divide by Zero | Instruments division and remainder operations with runtime checks that remediate when the divisor is zero. |
| Integer Overflow | Instruments arithmetic operations using *nsw/nuw* and inserts overflow checks where undefined behavior may occur. |
| Heap Out-of-Bounds | Instruments heap loads, stores, and `getelementptr` instructions with runtime checks to enforce heap bounds. |
| Stack Out-of-Bounds | Instruments stack `alloca`, loads, stores, and `getelementptr` instructions with runtime checks to enforce stack bounds. | 
| Null Pointer Dereference | Instruments pointer load and store instructions with runtime checks that detect null dereference. |
| Operation Masking | Replaces selected 'undesirable' function calls with guarded calls that validate operands before execution. |
| Free Nonheap | Instruments calls to `free` with runtime checks that ensure argument is a heap-allocated pointer. |
> [!NOTE]
> The CVE description must include an 'undesirable-function` field
> for the Operation Masking sanitizer to be applied. If this field
> is not present, Operation Masking is not enabled. 

> [!NOTE]
> Here is a table of weakness identifiers and alternatives that can be used to
> activate specific sanitizers.
> | Weakness Identifiers | Sanitizer |
> | --- | --- |
> | `190` | Integer Overflow | 
> | `369` | Divide by Zero |
> | `476` | Null Pointer Dereference |
> | `590` | Free Nonheap |
> | `121`, `123`, `125`, `131`, `797`| Stack OOB |
> | `122`, `123`, `125`, `131`, `797`| Heap OOB |   

## Remediation Strategies
Remediation strategies define how sanitizers respond to detected errors. If a sanitizer does not specify a remediation strategy in its internal data structure, the `continue` startegy is used by default. Certain
sanitizer-strategy combinations are invalid. When a combination is encountered, the implementation falls 
back to `continue`. 

| Remediation Strategy | Behavior |
| --- | --- |
| Continue | Invalid memory operations are ignored and return 0 |
| Exit | Inserts `exit` function call with specified exit code |
| None | Does not perform remediation | 
| Recover | Transfer control to a recovery handler using `longjmp` | 
| Saturate (Sat) | Use saturated arithmetic |
| Widen | Widen potentially overflowing intermediate operations |
| Wrap | Use 2's complement arithmetic | 

> [!WARNING]
> The default remediation stategy 
> for arithmetic sanitizers is **`Wrap`**, both when 
> no strategy is specified and when
> an invalid sanitizer-strategy combination
> is encountered.

> [!WARNING]
> The default remediation strategy for
> memory sanitizers is **`Continue`**, both when no
> strategy is specified and when an invalid 
> sanitizer-strategy combination is encountered.

> [!NOTE]
> Unlike the other strategies, **`recover`** is semi-automatic.
> This strategy requires the programmer to insert a
> *jmp_buf* construct within the program and insert 
> additional logic to cause the program to call setjmp
> to transfer control to a recovery handler.

## Example 
```C
// Divide by Zero
int div_zero_main(int argc, const char* argv[]) {    
    int math = (int) (42.0 / (float)argc);
    return 42 % argc + math / argc;
}

int main(int argc, const char* argv[]) {
    // call with 1 arg to trigger div by zero
    return div_zero_main(argc-2, argv);
}
```

**Pre-Instrumented IR** 
```llvm
; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @div_zero_main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store ptr %1, ptr %4, align 8
  %6 = load i32, ptr %3, align 4
  %7 = sitofp i32 %6 to float
  %8 = fpext float %7 to double
  %9 = fdiv double 4.200000e+01, %8
  %10 = fptosi double %9 to i32
  store i32 %10, ptr %5, align 4
  %11 = load i32, ptr %3, align 4
  %12 = srem i32 42, %11
  %13 = load i32, ptr %5, align 4
  %14 = load i32, ptr %3, align 4
  %15 = sdiv i32 %13, %14
  %16 = add nsw i32 %12, %15
  ret i32 %16
}
```

**Post-Instrumented IR**
```llvm
; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @div_zero_main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store ptr %1, ptr %4, align 8
  %6 = load i32, ptr %3, align 4
  %7 = sitofp i32 %6 to float
  %8 = fpext float %7 to double
  %9 = fcmp oeq double %8, 0.000000e+00
  br i1 %9, label %12, label %10

10:                                               ; preds = %2
  %11 = fdiv double 4.200000e+01, %8
  br label %13

12:                                               ; preds = %2
  call void @resolve_remediation_behavior()
  br label %13

13:                                               ; preds = %10, %12
  %14 = phi double [ 4.200000e+01, %12 ], [ %11, %10 ]
  %15 = fptosi double %14 to i32
  store i32 %15, ptr %5, align 4
  %16 = load i32, ptr %3, align 4
  %17 = icmp eq i32 %16, 0
  br i1 %17, label %20, label %18

18:                                               ; preds = %13
  %19 = srem i32 42, %16
  br label %21

20:                                               ; preds = %13
  call void @resolve_remediation_behavior()
  br label %21

21:                                               ; preds = %18, %20
  %22 = phi i32 [ 0, %20 ], [ %19, %18 ]
  %23 = load i32, ptr %5, align 4
  %24 = load i32, ptr %3, align 4
  %25 = icmp eq i32 %24, 0
  br i1 %25, label %28, label %26

26:                                               ; preds = %21
  %27 = sdiv i32 %23, %24
  br label %30

28:                                               ; preds = %21
  call void @resolve_remediation_behavior()
  %29 = sdiv i32 %23, 1
  br label %30

30:                                               ; preds = %26, %28
  %31 = phi i32 [ %29, %28 ], [ %27, %26 ]
  %32 = add nsw i32 %22, %31
  ret i32 %32
}

define internal void @resolve_remediation_behavior() {
  call void @exit(i32 3)
  ret void
}
```

This example demonstrates remediation applied to a divide-by-zero in
the function `div_zero_main`. The instrumented IR contains a call to 
`resolve_remediation_behavior`. When a remediation strategy is selected, the compiler generates a helper function that implements the corresponding remediation strategy.
At runtime, this helper is invoked when a violation is detected, and execution proceeds according to the selected strategy.
In this example, the `EXIT` strategy is specified, causing the program to terminate early with a sanitizer-specific
exit code.

```C
// Out-of-bounds Write 
#include <stdlib.h>
int main() {
  char *p = malloc(16);
  p[45] = 100;
  return 0;
}
```
**Pre-Instrumented IR**
```llvm
; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca ptr, align 8
  store i32 0, %1, align 4
  %3 = call noalias ptr @malloc(i64 noundef 16) #2
  store ptr %3, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  %5 = getelementptr inbounds i8, ptr %4, i64 42
  store i8 100, ptr %5, align 1
  ret i32 0
}
```

**Post-Instrumented IR**
```llvm
; Function Attrs: noinline nounwind optnone uwtable
define dso_local @main() #0 {
  %1 = alloca i32, align 4
  call void @resolve_stack_obj(ptr %1, i64 4)
  %2 = alloca ptr, align 8
  call void @resolve_stack_obj(ptr %2, i64 8)
  store i32 0, ptr %1, align 4
  %3 = call ptr @resolve_malloc(i64 16)
  store ptr %3, ptr %2, align 8
  %4 = load ptr, ptr %2, align 8
  %5 = getelementptr i8, ptr %4, i64 45
  %6 = call ptr @resolve_gep(ptr %4, ptr %5)
  call void @resolve_bounds_check_st_ty_i8(ptr %6, i8 100)
  call void @resolve_invalidate_stack(ptr %1, ptr %1)
  call void @resolve_invalidate_stack(ptr %2, ptr %2)
  ret i32 0
}
```
This example demonstrates an out of bounds write in `main`.
The instrumented IR contains calls to `resolve_stack_obj`,
`resolve_gep`, and `resolve_invalidate_stack`. The `resolve_stack_obj`
function records stack allocations as shadow object in the libresolve runtime, while
`resolve_malloc` records heap allocations in the same shadow memory.

The `resolve_gep` function enforces spatial safety by performing a shadow object lookup
on the base pointer and checking whether the derived pointer lies within the allocation 
bounds. If a derived pointer falls outside of these boudns, `resolve_gep` returns a
tainted pointer, a pointer whose address exceeds the allocation range. 

In the subsequent
`resolve_bounds_check_st_ty_i8` call the pointer is checked for taintedness. If the pointer
is tainted, the specified resolve strategy is applied; otherwise the load or store
is allowed to proceed.

At function exit, the compiler inserts a call to `resolve_invalidate_stack` to mirror
stack unwinding by invalidating the corresponding shadow objects.    


## Testing
To verify correct IR transformations and binary behavior, we developed a testing suite with regression testing. The suite contains testcases for each sanitizer and tests that the resulting binaries perform the intended behaviors with and without the remediation instrumentation. The testing suite can be found in [`llvm-plugin/tests/regression`](/llvm-plugin/tests/regression) and the tests can be executed by calling *make*. 