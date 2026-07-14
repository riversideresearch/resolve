# Command Line Interface

The `resolve` command line interface is the primary user interface to **RESOLVE**. **RESOLVE** exposes subcommands for each action and the pages under this section document each one, while the [examples](../../examples/crash-analysis.md) walk through them end to end.

## Setup

`resolve` ships with **RESOLVE** (see the [Installation guide](../../installation.md) to grab it, or [Development guide](../../development/building-from-source.md) to build it).

A pre-built installs place the CLI (and its subcommands) under the install prefix: `/opt/resolve/bin`.

```bash
# use the full path
/opt/resolve/bin/resolve --help

# ...or add the install prefix to PATH once, then use `resolve`
export PATH="/opt/resolve/bin:$PATH"
resolve --help
resolve version
```

`resolve` with no arguments (or `resolve help`) lists the subcommands available
on your install, and `resolve help <subcommand>` forwards `--help` to that
subcommand:

```bash
resolve help                # list available subcommands
resolve help crash-analysis # show a subcommand's own options
```

## Subcommands

## `reach`

Runs the static reachability analysis: given a `vulnerabilities.json` and
extracted facts, it searches for a call path from the program's entry point to
each flagged sink.

```bash
resolve reach -i vulnerabilities.json -f main.facts -o out.json
```

Inputs:

- [`vulnerabilities.json`](../../concepts/vulnerabilities-json.md) (`-i`) — the vulnerabilities to check
- extracted [facts](../facts.md) files (`-f`)
- optionally, the entry point (`-e`, defaults to `main`) and source path (`-s`) for vcpkg overlays

Outputs:

- a JSON report of which sinks are reachable (`-o`)

See the [Reach component docs](../reach.md) for the full reference, or the
[reachability example](../../examples/reachability.md) for a walkthrough
(including how to produce the facts file).

## `input-synthesis`

Drives a coding agent through CVE analysis and improvement, (AI-enhanced)
reachability analysis, and finally input synthesis.

```bash
# full pipeline: <agent> <cve.json> <output-dir>
resolve input-synthesis run_all claude cve.json out/

# or, for a well-understood vulnerability, synthesize a triggering input directly
resolve input-synthesis synthesize claude cve.json out/synthesize
```

Inputs:

- a CVE description (consumed by an LLM, so any human-readable file works)

Outputs (improve-CVE):

- `CVE.<ext>` — improved CVE description (same format as input)
- `necessary_conditions/` — refined necessary conditions
- `sufficient_conditions/` — refined sufficient conditions

Outputs (reachability):

- `reachability.md` — revised reachability analysis
- `conclusion.md` — one-paragraph summary
- `input-synthesis/` — synthesized inputs and supporting scripts (if applicable)

The `synthesize` subcommand runs only the final input-synthesis step, driving it
directly from the CVE description without the improve-CVE/reachability stages,
for lightweight cases where the vulnerability is already understood. See the
[Input Synthesis docs](input-synthesis.md) for every stage and flag, or the
[input synthesis example](../../examples/input-synthesis.md) for a walkthrough.

## `crash-analysis`

Runs a crash analysis workflow, agnostic to the specifics of the input. Point a
coding-agent backend (`claude`, `codex`, or `opencode`) at a folder of crash
evidence, optionally alongside the source tree:

```bash
resolve crash-analysis claude -i folder_with_crash_files -s folder_with_source_code -o out
```

Inputs:

- crash folder (`-i`) — can contain any relevant files (core dumps, sanitizer logs, reproducers)
- source folder (`-s`, optional) — helps match function symbols and examine logic

Outputs:

- `vulnerabilities.json` — for use with resolve tools or deduplication
- `report.md` — a final explanation of the analysis performed
- `synthesis.md` — (internal) original insights gleaned from cursory analysis
- `thesis.md` — (internal) thesis containing conclusion on crash origin
- `antithesis.md` — (internal) pushback against the thesis

See the [Crash Analysis docs](crash-analysis.md) for the full reference, or the
[crash analysis example](../../examples/crash-analysis.md) for a walkthrough.

## `sbom`

Searches NVD for known vulnerabilities in an SBOM and generates a
`vulnerabilities.json` with the results.

```bash
resolve sbom example.spdx.json -o vulnerabilities.json -L ollama
```

Inputs:

- `<project>.spdx.json` (positional) — a CMake-generated software bill of materials (SBOM) in SPDX format

Outputs:

- `vulnerabilities.json` (`-o`) — found vulnerabilities, for use by the `reach` subcommand

The optional `-L` flag selects an LLM backend (`gemini`, `ollama`, or
`opencode`) used to pin down each CVE's affected file and function; omit it to
leave those fields as `UNKNOWN`. See the [SBOM docs](sbom.md) for the full option
reference, or the [SBOM example](../../examples/sbom.md) for a walkthrough.
