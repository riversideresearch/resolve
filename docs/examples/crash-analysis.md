# Crash Analysis Example

**RESOLVE** can turn raw crash evidence (core dumps, stack traces, sanitizer logs, reproducers) into a structured [`vulnerabilities.json`](../concepts/vulnerabilities-json.md) by driving a coding agent through a guided investigation.

This is pretty neat, becaues the rest of the toolchain can use this to query and fix the crashing program. The `vulnerabilities.json` this pipeline emits is exactly what [reachability](reachability.md) and [remediation](remediation.md) consume.

This guide walks through analyzing a crashing program with the `resolve` CLI, and has supplemental source code in the [GitHub repository](https://github.com/riversideresearch/resolve/tree/main/examples/crash-analysis/). For the full command reference, see the [crash analyzer component docs](../components/resolve-cli/crash-analyzer.md).

## The Program

Consider a program with a `greet` function that copies an attacker-controlled string into a fixed 8-byte stack buffer with no bounds check:

```c
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[8];
    strcpy(buf, name);
    printf("Hello, %s!\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 0;
    greet(argv[1]);
    return 0;
}
```

The crash happens *inside* `strcpy`, but `strcpy` is not the bug — the vulnerable function is `greet`, which owns the undersized buffer. A core value of crash analysis is walking up from the crashing frame (a symptom) to the project function that is actually at fault.

## Producing Crash Evidence

Crash analysis reasons over evidence, so first we need a crash to reason about. Build the program under [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) and run it with an oversized argument, saving the sanitizer report:

```bash
clang -g -O0 -fsanitize=address main.c -o greet
./greet AAAAAAAAAAAAAAAAAAAAAAAAAAAA > crash/asan.log 2>&1
```

The resulting `crash/asan.log` explains the fault precisely: a [`stack-buffer-overflow`](https://cwe.mitre.org/data/definitions/121.html) write, inside `strcpy`, called from `greet` at `main.c:8`:

```txt
==...==ERROR: AddressSanitizer: stack-buffer-overflow on address ...
WRITE of size 29 at ... thread T0
    #0 ... in strcpy ...
    #1 ... in greet main.c:8:5
    #2 ... in main main.c:15:5
...
  This frame has 1 object(s):
    [32, 40) 'buf' (line 7) <== Memory access at offset 40 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow ... in strcpy
```

Everything the agent will inspect lives in a single *crash directory* (`crash/` here). Alongside the log, it helps to drop in a short note describing how the crash was produced:

```
crash/
├── asan.log     # the sanitizer report
└── repro.md     # how the crash was produced, and the reproducing input
```

!!! tip
    A crash directory can hold whatever evidence you have (core dumps, the crashing binary, reproducer inputs, logs, and build metadata). When a binary/core pair is available, the agent will use `gdb` to inspect it. More evidence yields a better-attributed result.

## Running Crash Analysis

Point `resolve crash-analysis` at the crash directory. Pass a coding-agent backend (`claude`, `codex`, or `opencode`) as the first argument, the crash directory with `-i`, the source tree with `-s`, and an output directory with `-o`:

```bash
resolve crash-analysis claude -i crash -s src -o out
```

!!! note
    The chosen agent's CLI (e.g. `claude`) must be installed and authenticated, since crash analysis runs it to perform the investigation. Passing `-s src` lets the agent resolve project-relative `affected-file` and source-level `affected-function` values; without it, attribution is limited to what the crash artifacts alone reveal.

Under the hood, `resolve crash-analysis` runs a four-stage [dialectic](https://en.wikipedia.org/wiki/Dialectic) so conclusions are challenged before they are committed. Each stage writes an intermediate report into the output directory:

1. **Synthesis** (`synthesis.md`): an objective, evidence-first inventory of the crash: artifacts, debugger findings, reproduction, and source evidence.
2. **Thesis** (`thesis.md`): the strongest affirmative case for each distinct vulnerability.
3. **Antithesis** (`antithesis.md`): rigorous pushback: symptom-vs-root-cause, over-broad CWEs, wrong attributions, duplicates, non-security crashes.
4. **Final**: reconciles the two into the two public artifacts, `vulnerabilities.json` and `report.md`.

```
out/
├── synthesis.md          # stage 1: objective evidence
├── thesis.md             # stage 2: affirmative case
├── antithesis.md         # stage 3: pushback
├── vulnerabilities.json  # final: the structured finding
└── report.md             # final: the reconciliation decision
```

## Interpreting the Result

The headline artifact is `out/vulnerabilities.json`. For our program, crash analysis will generate something like this:

```json
{
  "vulnerabilities": [
    {
      "cve-id": "CVE-greet-00001",
      "cve-description": "The greet function ... copies a caller-supplied string (argv[1], forwarded from main) into a fixed 8-byte stack buffer using strcpy with no bounds check ... causing a stack out-of-bounds write (stack-buffer-overflow) that AddressSanitizer detects and aborts on.",
      "package-name": "UNKNOWN",
      "package-version": "UNKNOWN",
      "cwe-id": "121",
      "cwe-name": "Stack-based Buffer Overflow",
      "affected-function": "greet",
      "affected-file": "main.c",
      "undesirable-function": "strcpy",
      "remediation-strategy": "exit"
    }
  ]
}
```

The companion `out/report.md` is the reconciliation decision document: it explains the evidence behind each emitted field, which thesis claims were rejected, and which antithesis objections were accepted.

!!! note
    Crash analysis is agent-driven, so wording and emphasis vary between runs. What stays stable is the structure: a validated `vulnerabilities.json` and a `report.md` that justifies every field against the evidence. The emitted `vulnerabilities.json` is checked against the **RESOLVE** schema before the command succeeds.

## Next Steps

The `out/vulnerabilities.json` produced here is a drop-in input for the rest of the toolchain. You can feed it to [reachability](reachability.md) to confirm the affected function is reachable from an entry point, or to [remediation](remediation.md) to automatically instrument a fix at compile time.
