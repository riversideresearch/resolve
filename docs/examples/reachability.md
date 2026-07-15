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

First, describe the vulnerability we want to analyze in a JSON file (let's call it [`vulnerabilities.json`](../concepts/vulnerabilities-json.md) on disk). Each entry in the array is a *sink* (a function we would like to try to reach). All of the following fields are required, and will be fed-through into our final report:

```json
{
    "vulnerabilities": [
        {
            "cve-id": "CVE-0000-00000",
            "cve-description": "Null pointer dereference reachable from the program entry point.",
            "package-name": "reachability-example",
            "package-version": "vers:generic/*",
            "cwe-id": "476",
            "cwe-name": "NULL Pointer Dereference",
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

## Extracting the Facts

Next, pull the embedded facts back out of the binary into a `main.facts` file with `resolve get-facts`:

```bash
resolve get-facts -i main
```

This writes `main.facts` (alongside a compressed `main.facts.zst`) into the current directory.

## Running the Reachability Query

Now we have everything [`resolve reach`](../components/reach.md) needs: the vulnerability specification and the facts. Point it at both and choose an output path for the report:

```bash
resolve reach -i vulnerabilities.json -f main.facts -o out.json
```

!!! tip
    If your entry point is not `main`, pass `-e <function>` to `resolve reach`. For projects with a vcpkg source tree, pass `-s <src-dir>` so the report can additionally check whether the pinned package version falls in the vulnerable range.

`resolve reach` locates the entry point (`main` by default), locates each sink in the facts, and searches the control-flow graph for a path between them. Along the way it prints what it found:

```txt
Found function 'main' in module 'src/main.c'
Found function 'do_npd' in module 'src/main.c'
[RW]: Invoking reach 'reach -f main.facts -i reach_wrap_input.json -o reach_wrap_output.json'
[RW]: Wrote out.json.
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
                    "Function(main) ((1556769911, 9))",
                    "DirectCall -> Function(do_npd) ((1556769911, 1))"
                ],
                "control_flow_path": [
                    "Function(main) ((1556769911, 9))",
                    "Contains -> BasicBlock() ((1556769911, 10))",
                    "DirectCall -> Function(do_npd) ((1556769911, 1))"
                ]
            }
        }
    ]
}
```

The `call_path` is the human-readable answer: `main` makes a `DirectCall` to `do_npd`, so the vulnerability is reachable. The `control_flow_path` is the same route at basic-block granularity.

!!! note
    The classification is **potentially reachable (statically reachable)**, not **explicitely exploitable**. Reachability analysis only proves that a path exists in the control-flow graph; it does not prove a concrete input can drive execution down that path. Producing such an input is the job of [input synthesis](input-synthesis.md).

### Other Classifications

Depending on what `resolve reach` finds, a sink can come back as:

| `classification` | `conclusion` | Meaning |
| --- | --- | --- |
| `potentially reachable` | Statically Reachable | A control-flow path from the entry point to the affected function was found. |
| `unreachable` | Not Reachable | The function exists in the program, but no path reaches it from the entry point. |
| `unreachable` | Not Found | The affected function was not found in the compiled program metadata (e.g. it was inlined, dead-code eliminated, or never linked in). |

## TDLR (Quick Reference)

Given source code, you can run a reachability query with:

```bash
resolvecc main.c -o main
resolve get-facts -i main
resolve reach -i vulnerabilities.json -f main.facts -o out.json
```

!!! tip
    Once a path is confirmed, synthesize a concrete triggering input with input synthesis (above), or instrument a fix at compile time with [remediation](remediation.md).


