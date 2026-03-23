# Input Synthesis

Scripts for driving coding agents to perform CVE analysis, reachability analysis, and input synthesis. The pipeline takes a CVE description as input, improves it through structured reasoning, determines whether the vulnerability is reachable in a target project, and attempts to synthesize a triggering input.

## Example

Enter the root directory of the project of interest and:
```bash
# Run the full pipeline
python3 -m resolve.input_synthesis run_all claude cve.json out/

# Or run each step individually
python3 -m resolve.input_synthesis setup claude cve.json
python3 -m resolve.input_synthesis improve_CVE claude cve.json out/improve_cve
python3 -m resolve.input_synthesis reachability claude cve.json out/improve_cve out/reachability
```

## Overview

The scripts work by delegating reasoning to coding agents (Claude, Codex, or OpenCode) through carefully structured prompts. Two patterns from `agent.py` are used throughout:

**Debate** (`run_dialectic`): A MAD-like debate for analyzing a claim from scratch. One pass argues that the claim is correct, another argues that it is incorrect without seeing the first answer, and a final pass reconciles the two.

**Challenge and revise** (`run_critique`): A lighter pattern for improving an existing document. One pass assumes the document's conclusions are wrong and tries to show why, and a second pass updates the document based on the valid points.

## Prerequisites

- Python 3 with `python3` on `PATH`.
- At least one supported coding-agent CLI installed on `PATH` and authenticated:
  - `claude` for `claude`
  - `codex` for `codex`
  - `opencode` for `opencode`
- A writable `/tmp` directory (scripts use temporary workspaces under `/tmp`).
- Build/install tooling required by the target project (compiler, package managers, etc.).

## Failure behavior

- If an agent subprocess exits non-zero, scripts print `agent failed with exit code ...` and exit non-zero.
- `improve_CVE.py` and `reachability.py` fail if `<output_path>` exists unless `--overwrite` is provided.
- `reachability.py` fails fast if `<improve_cve_path>` or expected condition directories are missing.
- If required generated artifacts are missing (for example, a prompt did not produce an expected file), scripts fail with an explicit error.
- Missing input files or missing agent executables currently raise `FileNotFoundError` tracebacks.

## Pipeline

### 1. `setup.py`

Prepares the target project for analysis. Given a CVE description, it checks out the affected version, maps the project architecture, installs dependencies (ensuring source code is available locally for analysis), and builds the project.

```
python3 -m resolve.input_synthesis setup <agent> <cve_path>
```

### 2. `improve_CVE.py`

Improves a CVE description and decomposes it into necessary and sufficient conditions for triggering the vulnerability.

```
python3 -m resolve.input_synthesis improve_CVE <agent> <cve_path> <output_path> [--overwrite]
```

Steps:
1. **CVE improvement**: Runs a debate over the original CVE, then rewrites it as an improved CVE description.
2. **Necessary condition inference**: Identifies conditions that must all be true for the vulnerability to trigger (conjunctive).
3. **Necessary condition refinement**: Challenges each necessary condition individually and revises it if needed.
4. **Sufficient condition inference**: Identifies conditions where any single one being true guarantees the vulnerability triggers (disjunctive).
5. **Sufficient condition refinement**: Challenges each sufficient condition individually and revises it if needed.

Notes:
- If no necessary or sufficient conditions are inferred, the script prints a warning and continues.
- Internal scratch data used during challenge passes is not copied into the final output directory.
- If `<output_path>` already exists, the script fails unless `--overwrite` is provided.

Output directory contains:
- `CVE.<ext>` -- improved CVE description (same format as input)
- `necessary_conditions/` -- refined necessary conditions
- `sufficient_conditions/` -- refined sufficient conditions

### 3. `reachability.py`

Determines whether the vulnerability is reachable in the target project and attempts to synthesize a triggering input.

```
python3 -m resolve.input_synthesis reachability <agent> <cve_path> <improve_cve_path> <output_path> [--overwrite]
```

Where `<improve_cve_path>` is the output directory from `improve_CVE.py`.

If `<output_path>` already exists, the script fails unless `--overwrite` is provided.

Steps:
1. **Reachability analysis**: Checks whether the necessary conditions are simultaneously satisfiable via user input, then whether any sufficient condition is satisfiable. Concludes "triggerable", "not triggerable", or "inconclusive".
2. **Reachability challenge**: Challenges the reachability analysis and produces a revised version.
3. **Input synthesis and conclusion**: If triggerable or inconclusive, attempts to synthesize a concrete input that triggers the vulnerability. Writes a summary to `conclusion.md`.

Output directory contains:
- `reachability.md` -- revised reachability analysis
- `conclusion.md` -- one-paragraph summary
- `input-synthesis/` -- synthesized inputs and supporting scripts (if applicable)

### `run_all.py`

Runs the full pipeline (setup, CVE improvement, reachability) in sequence.

```
python3 -m resolve.input_synthesis run_all <agent> <cve_path> <output_path> [--overwrite]
```

This calls `setup.run()`, `improve_CVE.run()`, and `reachability.run()` directly, placing artifacts under `<output_path>/improve_cve/` and `<output_path>/reachability/`.

## Supported agents

- `claude` -- Claude Code CLI
- `codex` -- OpenAI Codex CLI
- `opencode` -- OpenCode CLI
