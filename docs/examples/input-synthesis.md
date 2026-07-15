# Input Synthesis Example

**RESOLVE** input synthesis (given a CVE description) drives a coding agent to improve the description, reasons about what it takes to trigger the bug, and then synthesizes a concrete triggering input (a proof-of-vulnerability).

This guide walks through synthesizing an input for a small program with the `resolve` CLI, and has supplemental source code in the [GitHub repository](https://github.com/riversideresearch/resolve/tree/main/examples/input-synthesis/). For the full breakdown of every phase, see the [input synthesis component docs](../components/resolve-cli/input-synthesis.md).

## The Program

Consider a program that reads a length-prefixed record from stdin: the first byte declares the payload length, the rest is the payload. `parse_record` trusts that declared length and copies it into a fixed 16-byte stack buffer:

```c
#include <stdio.h>
#include <string.h>

void parse_record(const unsigned char *payload, unsigned char len) {
    char buf[16];
    memcpy(buf, payload, len);   // len is attacker-controlled; buf is only 16 bytes
    printf("parsed %u bytes\n", len);
}

int main(void) {
    unsigned char data[256];
    size_t n = fread(data, 1, sizeof data, stdin);
    if (n < 1)
        return 0;
    parse_record(data + 1, data[0]);   // first byte is the declared length
    return 0;
}
```

A declared length of 16 or less is harmless; anything larger overflows `buf`. While it might be easy for a human to come up with a concrete input for this example, there are more nuanced input-triggered vulnerabilities in the wild that this is not the case for. The input synthesis pipeline will try to tell us for any given vulnerability, **exactly what bytes or payload trigger it**.

## Describing the Vulnerability

Input synthesis starts from a [**RESOLVE** JSON CVE description file](../concepts/vulnerabilities-json.md) (`vulnerabilities.json`). This description is what the pipeline reasons over, so it should name the affected function, the bug class, and the input condition that triggers it:

!!! tip
    Because this is an agentic pipeline, the more information you can provide in this context, the better. You can supply any additional json data in this file you'd like to the agent, it doesn ***not*** need to be valid **RESOLVE** metadata.

```json
{
    "vulnerabilities": [
        {
            "cve-id": "CVE-recordparser-00001",
            "cve-description": "recordparser 1.0.0 reads a length-prefixed record from stdin, where the first byte declares the payload length. parse_record copies that many bytes into a fixed 16-byte stack buffer with memcpy and no bounds check, so a declared length greater than 16 causes a stack-based buffer overflow (CWE-121).",
            "package-name": "recordparser",
            "package-version": "1.0.0",
            "cwe-id": "121",
            "cwe-name": "Stack-based Buffer Overflow",
            "affected-function": "parse_record",
            "affected-file": "main.c",
            "remediation-strategy": "exit"
        }
    ]
}
```

!!! tip
    This is the same `vulnerabilities.json` shape the other tools use, so a finding produced by [crash analysis](crash-analysis.md) can be fed straight into input synthesis.

## Running the Pipeline

Run the pipeline from the root of the target project. Pass a coding-agent backend (`claude`, `codex`, or `opencode`), the CVE file, and an output directory:

```bash
resolve input-synthesis run-all claude cve.json out/
```

!!! note
    The chosen agent's CLI (e.g. `claude`) must be installed and authenticated, since each phase runs it to perform the analysis. `run-all` executes the phases in sequence; you can also run them individually (`setup`, `improve-cve`, `reachability`) — see the [component docs](../components/resolve-cli/input-synthesis.md).

`run-all` chains four phases, each building on the last:

1. **Setup**: checks out the affected version, maps the project, installs dependencies, and builds it, so later phases have a real target to analyze.
2. **Improve CVE**: sharpens the description through a debate pass, then decomposes it into necessary conditions (all must hold) and sufficient conditions (any one guarantees the trigger).
3. **Reachability**: decides whether those conditions are simultaneously satisfiable from user input, concluding triggerable, not triggerable, or inconclusive. (For the static, compiler-facts flavor of reachability, see the [reachability example](reachability.md).)
4. **Input synthesis**: if triggerable, synthesizes a concrete input that satisfies the conditions and writes a summary to `conclusion.md`.

## Interpreting the Result

The pipeline populates `out/` with the artifacts from each phase:

```
out/
├── improve_cve/
│   ├── CVE.json                # sharpened description
│   ├── necessary_conditions/   # conditions that must all hold
│   └── sufficient_conditions/  # conditions that each suffice
└── reachability/
    ├── reachability.md         # the triggerability analysis
    ├── conclusion.md           # one-paragraph summary
    └── input-synthesis/        # the synthesized input(s)
```

Our main artifacts are the synthesized inputs under `out/reachability/input-synthesis/`. For our program this contains one instance of bytes that can overflow the buffer: a declared length past 16 followed by enough payload. The generated `poc.bin` will look something like this:

```
00000000: 1141 4141 4141 4141 4141 4141 4141 4141  .AAAAAAAAAAAAAAA
00000010: 4141                                     AA
```

The first byte of `0x11` (declaring 17 payload bytes) is followed by 17 bytes of payload (one more than `buf` can hold). Feeding this to the program re-triggers the overflow:

```bash
./recordparser < out/reachability/input-synthesis/poc.bin
```

`out/reachability/conclusion.md` summarizes the outcome in a sentence or two — whether the vulnerability was found triggerable and how the synthesized input exercises it.

!!! note
    Given that input synthesis is agent-driven, the exact bytes, filenames, and any helper scripts under `input-synthesis/` vary between runs.

!!! tip
    With a proof-of-vulnerability in hand, you can instrument a compile-time fix for the same finding with [remediation](remediation.md).
