# Remediation Example

**RESOLVE** can automatically remediate vulnerabilities upon program compilation using [CVEAssert](../../components/resolve-cveassert), an LLVM pass we developed to instrument programs with sanitizers.

This guide explains remediating a simple null-pointer dereference example with **RESOLVE**, and has supplemental source code in the [GitHub repository](https://github.com/riversideresearch/resolve/tree/main/examples/remediation/).

## The Program

Consider a program, like follows:

```c
#include <stdio.h>

int main(int argc, char *argv[]) {
    printf("Hello, UB!\n");
    int r = *(int*)0x0; // guaranteed segfault
    printf("Oh, I didn't crash?\n");
    return 0;
}
```

What do you think would happen if we ran this?

Here's the answer:

```bash
> clang main.c -o main
> ./main
Hello, UB!
Segmentation fault
```

Clearly, we are doing a null pointer dereference on line 5, with:

```c
int r = *(int*)0x0;
```

This is fairly obvious, but certain null pointer dereferences in real programs might not be so obvious. Let's just say for now that we wanted to use **RESOLVE** to fix this vulnerability, without touching the code at all.

## A Vulnerability Specification

To start with, we must create a json file specifying what we want resolve to fix. In this case, we need to know both the CWE ([Common Weakness Enumeration](https://cwe.mitre.org/)) number corresponding to the vulnerability type, and the affected function we want to sanitize.

According to the **RESOLVE** vulnerabilities.json documentation, we should create a json file like so: (let's just call it `vulnerabilities.json` on disk)

```json
{
    "vulnerabilities": [
        {
            "cwe-id": "476",
            "affected-function": "main",
            "affected-file": "main.c"
        }
    ]
}
```

!!! note
    In this case, some "required" fields (`cve-id`) are not actually required, since CVEAssert itself does not consume them. You can still provide them, if you'd like.

To see a full list of supported CWE IDs, see the [CVEAssert documentation](../components/resolve-cveassert.md/#common-mappings).

!!! tip
    If you wanted to remediate multiple vulnerabilities across multiple functions, you could define each one in the `vulnerabilities` array, and CVEAssert will sanitize each one.

## Compiling With Our Specification

To use our newly minted specification to remediate our program, we can invoke the **RESOLVE** compiler as if it were `clang`, passing it `-fcve-assert` with a path to our specification:

```bash
resolvecc main.c -o main -fcve-assert vulnerabilities.json
```

You'll see that `resolvecc` outputs some resulting LLVM IR transformations to stdout, showing exactly how it's instrumented the prorgam, which indicates a successful compilation.

Now, if we run the resulting program, no more vulnerability!

```txt
> ./main
Hello, UB!
Oh, I didn't crash?
```

## CMake

For larger projects, you will often want **RESOLVE** to run within the context of a CMake build, here's an example of how you can do that:

```cmake
set(CMAKE_C_COMPILER "resolvecc") 
set(CMAKE_CXX_COMPILER "resolvecc")

target_compile_options(${YOUR_TARGET} PRIVATE -fcve-assert vulnerabilities.json)
```
