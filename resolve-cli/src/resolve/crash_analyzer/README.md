# Agent Smith (Crash Analyzer)

Scripts for driving coding agents to perform crash analysis. The pipeline takes input files regarding the crash and codifies it through structured reasoning.

The agent will first examine the input folders and craft a `synthesis.md` file with objective facts about the crash. The agent will then create both a `thesis.md` and `antithesis.md` which then get reconciled into the `vulnerabilities.json` output and the `report.md`.

## Example

Using the resolve-cli:
```bash
resolve crash-analyzer codex -i folder_with_crash_files # or:
resolve crash-analyzer codex -i folder_with_crash_files -s folder_with_source_code
```

## Overview

The scripts work by delegating reasoning to coding agents (Claude, Codex, or OpenCode) through carefully structured prompts. 

## Prerequisites

- Python 3 with `python3` on `PATH`.
- At least one supported coding-agent CLI installed on `PATH` and authenticated:
  - `claude` for `claude`
  - `codex` for `codex`
  - `opencode` for `opencode`
- A writable `/tmp` directory (scripts use temporary workspaces under `/tmp`).
- Optional, but helpful: Build/install tooling required by the target project (compiler, package managers, etc.).
