# Reachability Example

**RESOLVE** can statically determine whether a known vulnerability is *reachable* (whether a call path exists from a program's entry point to the affected function).

This guide walks through checking reachability for a simple [null-pointer dereference](https://cwe.mitre.org/data/definitions/476.html) using the `resolve` CLI, and has supplemental source code in the [GitHub repository](https://github.com/riversideresearch/resolve/tree/main/examples/reachability/).

## The Program

Consider a program with a vulnerable function `do_npd`, which dereferences whatever pointer it is handed, and a `main` that calls it with a `NULL` pointer (`0x0`):

```c
void do_npd(void *ptr) {
    *(int *)ptr = 0;
}

int main(void) {
    do_npd(0x0);
    return 0;
}
```

We want to ask **RESOLVE**: starting from `main`, can execution actually reach `do_npd`? In this tiny program the answer is obvious, but in a real codebase the affected function might sit behind many layers of calls, and the real reachability is not immediately clear.

## A Vulnerability Specification

First, describe the vulnerability in a [`vulnerabilities.json`](../concepts/vulnerabilities-json.md) file on disk. Each entry identifies one affected function, which is called a sink.

```json
{
    "vulnerabilities": [
        {
            "cve-id": "CVE-0000-00000",
            "package-name": "reachability-example",
            "package-version": "vers:generic/*",
            "affected-function": "do_npd",
            "affected-file": "main.c"
        }
    ]
}
```

!!! tip
    To analyze several vulnerabilities at once, add more entries to the `vulnerabilities` array. The final report will contain results for each sink independently.

## Compiling With `resolvecc`

Reachability analysis runs on program *facts* (see: [RESOLVE facts](../components/facts.md)). **RESOLVE** generates these facts at compile time and embeds them directly into the binary. To produce them, compile with the [**RESOLVE** compiler, `resolvecc`](../components/resolve-cc.md), exactly as you would with `clang`:

```bash
resolvecc main.c -o main
```

## Running the Reachability Query

[`resolve reach`](../components/reach.md) reads embedded facts directly from the compiled ELF. Pass the path of the program and select an output file:

```bash
resolve reach -i vulnerabilities.json -f main -o out.json
```

!!! tip
    If your entry point is not `main`, pass `-e <function>` to `resolve reach`. For projects with a vcpkg source tree, pass `-s <src-dir>` so the report can additionally check whether the pinned package version falls in the vulnerable range.

!!! note
    If you need a separate facts file, use `resolve get-facts -i main`. This command writes `main.facts` and `main.facts.zst`. You can pass `main.facts` to `resolve reach`.

`resolve reach` locates the entry point and each sink. Then it searches the control-flow graph for a path.

```txt
[REACH] Loaded 1 facts modules from 1 input files.
[REACH] Built a libreach graph with 3 edges.
[REACH] Wrote 'out.json'.
```

## Interpreting the Report

The report in `out.json` classifies each sink and, when it is reachable, spells out the path that was found:

```json
{
    "reachability_results": [
        {
            "cve_id": "CVE-0000-00000",
            "classification": "potentially reachable",
            "justification": {
                "conclusion": "Statically Reachable",
                "reason": "Control Flow Graph analysis found the following candidate path...",
                "call_path": [
                    "Function(main) ((0, 9))",
                    "DirectCall -> Function(do_npd) ((0, 1))"
                ],
                "control_flow_path": [
                    "Function(main) ((0, 9))",
                    "Contains -> BasicBlock(0) ((0, 10))",
                    "DirectCall -> Function(do_npd) ((0, 1))"
                ]
            }
        }
    ]
}
```

`call_path` gives an exact answer here: `main` makes a `DirectCall` to `do_npd`, so the vulnerability is statically reachable! The `control_flow_path` is the same route at basic-block granularity.

!!! note
    The classification is **potentially reachable (statically reachable)**, not **explicitly exploitable**. Reachability analysis proves that a control-flow path exists. It does not prove that a concrete input can use that path. [Input synthesis](input-synthesis.md) produces such an input.

### Other Classifications

Depending on what `resolve reach` finds, a sink can come back as:

| `classification` | `conclusion` | Meaning |
| --- | --- | --- |
| `potentially reachable` | Statically Reachable | A control-flow path from the entry point to the affected function was found. |
| `unreachable` | Not Reachable | The function exists in the program, but no path reaches it from the entry point. |
| `unreachable` | Not Found | The affected function was not found in the compiled program metadata (e.g. it was inlined, dead-code eliminated, or never linked in). |

## TLDR (Quick Reference)

Given source code, you can run a reachability query with:

```bash
resolvecc main.c -o main
resolve reach -i vulnerabilities.json -f main -o out.json
```

!!! tip
    Once a path is confirmed, synthesize a concrete triggering input with input synthesis (above), or instrument a fix at compile time with [remediation](remediation.md).
