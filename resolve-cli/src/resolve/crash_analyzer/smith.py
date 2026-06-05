# Copyright (c) 2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import subprocess
import sys
from pathlib import Path

from resolve.agent_utils.agent import run_prompt
from resolve.agent_utils.utils import prepare_output_path, require_file

from .utils import validate_vulnerabilities_json


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    prog = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description="Generate RESOLVE vulnerability artifacts from crash evidence.",
        epilog=f"""Examples:
  {prog} codex -i crash_dir
  {prog} codex -i crash_dir -s source_dir
  {prog} claude -i crash_dir -s source_dir -o out/crash-analysis""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "agent",
        choices=("claude", "codex", "opencode"),
        help="Coding agent backend to execute prompts with.",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="crash_dir",
        type=Path,
        required=True,
        help="Path to an input directory containing crash provenance and metadata.",
    )
    parser.add_argument(
        "-s",
        "--source",
        dest="source_dir",
        type=Path,
        help="Path to the source code directory.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        type=Path,
        default=Path("out"),
        help="Destination directory for final artifacts and intermediate reports.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output_path if it already exists.",
    )
    parser.add_argument(
        "--model",
        help="Optional model override passed through to the selected agent CLI.",
    )
    return parser.parse_args(argv)


def _source_context(source_dir: Path | None) -> str:
    if source_dir is None:
        return (
            "No source directory was provided. If source-level attribution is not "
            "supported by the crash artifacts, say so explicitly."
        )
    return (
        f"The source tree is available at `{source_dir}`. Use it to identify "
        "project-relative `affected-file` and source-level `affected-function` values."
    )


def _common_context(
    crash_dir: Path,
    source_dir: Path | None,
    output_path: Path,
    tmp_path: Path,
) -> str:
    return f"""
`{crash_dir}` contains crash artifacts for one or more crashes.
{_source_context(source_dir)}

Output directory: `{output_path}`
Temporary analysis directory: `{tmp_path}`

General requirements:
- Base every claim on inspected evidence: crash artifacts, core dumps, stack traces, registers, sanitizer logs, reproducers, debugger output, build metadata, and source code when available.
- Use tools available in the environment, including `gdb`, when a binary/core pair or reproducible crash is available. If a tool is unavailable or an artifact cannot be inspected, record that limitation.
- Do not update persistent agent instruction files such as `AGENTS.md`, `CLAUDE.md`, or `OPENCODE.md`.
- Do not invent package names, versions, functions, files, inputs, or root causes. Use `UNKNOWN` for package name or package version only when the artifacts and source tree do not provide credible evidence.
- Treat libc, libstdc++, allocator, signal-handler, sanitizer, and runtime frames as symptoms unless evidence shows they are the vulnerable component. Walk upward to the project function that passed bad data or performed the unsafe operation.
- Deduplicate findings by distinct root cause. Multiple cores or reproducers for the same vulnerable function/condition should normally produce one vulnerability entry.
"""


def run(
    agent: str,
    crash_dir: Path,
    source_dir: Path | None,
    output_path: Path,
    overwrite: bool,
    model: str | None = None,
) -> int:
    if not crash_dir.is_dir():
        raise ValueError(f"crash input directory does not exist: {crash_dir}")
    if source_dir is not None and not source_dir.is_dir():
        raise ValueError(f"source directory does not exist: {source_dir}")

    prepare_output_path(output_path, overwrite)

    tmp_path = output_path / "tmp"
    tmp_path.mkdir(parents=True, exist_ok=True)
    print(f"Using temporary workspace: {tmp_path}")

    synthesis_path = output_path / "synthesis.md"
    thesis_path = output_path / "thesis.md"
    antithesis_path = output_path / "antithesis.md"
    reconciliation_path = output_path / "reconciliation.md"
    vulnerabilities_path = output_path / "vulnerabilities.json"
    report_path = output_path / "report.md"
    common_context = _common_context(crash_dir, source_dir, output_path, tmp_path)

    synthesis_prompt = f"""
{common_context}

# Your task

Perform the initial crash investigation and write an objective evidence synthesis to `{synthesis_path}`.

The synthesis must be factual and evidence-first. Include:
- Artifact inventory: binaries, core files, reproducers, logs, source/build files, and metadata inspected.
- Debugger evidence: exact signal, crashing instruction/frame, thread/backtrace summary, relevant registers, fault address or arithmetic operands, mappings, and symbol/source-line information when available.
- Reproduction evidence: whether a reproducer exists, whether it was run, observed command/output/exit status, and whether it matches the crash artifacts.
- Source evidence: vulnerable operation candidates, caller/callee relationships, input-controlled values, package/project/version evidence, and project-relative source paths.
- Crash grouping: whether artifacts represent one root cause or multiple distinct root causes.
- Evidence gaps: important facts that could not be established.

Do not produce `vulnerabilities.json` in this stage.
"""

    run_prompt(agent, synthesis_prompt, model=model)
    require_file(synthesis_path, "crash synthesis")

    thesis_prompt = f"""
{common_context}

`{synthesis_path}` contains the objective crash evidence.

# Your task

Write `{thesis_path}`: the strongest evidence-backed affirmative case for each distinct vulnerability that should be emitted in RESOLVE `vulnerabilities.json`.

For each candidate vulnerability, include:
- Candidate ID using `CVE-<package-or-project>-00001`, incrementing for distinct root causes.
- Root-cause function and project-relative source file.
- Crash/security impact.
- CWE ID/name selection and why it is the most specific supported class.
- RESOLVE remediation strategy and any `undesirable-function` if the dangerous operation is in a callee while the caller is the affected function.
- Direct evidence citations from `{synthesis_path}`.

If the evidence supports no credible vulnerability, write that conclusion and explain why.
Do not produce `vulnerabilities.json` in this stage.
"""

    run_prompt(agent, thesis_prompt, model=model)
    require_file(thesis_path, "crash thesis")

    antithesis_prompt = f"""
{common_context}

`{synthesis_path}` contains the objective crash evidence.
`{thesis_path}` contains the affirmative vulnerability case.

# Your task

Write `{antithesis_path}`: a rigorous pushback against the thesis.

Challenge:
- Unsupported root-cause claims or assumptions.
- Cases where the top frame is only a symptom.
- Incorrect or overly broad CWE choices.
- Incorrect `affected-function`, `affected-file`, package, version, or remediation strategy.
- Duplicate vulnerabilities that should be merged by root cause.
- Crashes that are not security-relevant or cannot be credibly attributed.
- Missing debugger/source/reproducer evidence that should prevent JSON emission.

For every thesis claim you reject, explain the evidence-based reason. For every claim you accept, say why the antithesis could not refute it.
Do not produce `vulnerabilities.json` in this stage.
"""

    run_prompt(agent, antithesis_prompt, model=model)
    require_file(antithesis_path, "crash antithesis")

    reconciliation_prompt = f"""
{common_context}

Inputs:
- Evidence synthesis: `{synthesis_path}`
- Thesis: `{thesis_path}`
- Antithesis: `{antithesis_path}`

# Your task

Resolve the disagreement and write `{reconciliation_path}`.

The reconciliation is the final decision document before JSON generation. It must:
- List the final set of distinct root-cause vulnerabilities to emit, or explicitly state that the set is empty.
- For each emitted vulnerability, lock the exact values for `cve-id`, `cve-description`, `package-name`, `package-version`, `cwe-id`, `cwe-name`, `affected-function`, `affected-file`, `remediation-strategy`, and optional `undesirable-function`. The `cwe-id` value must be the numeric string only, such as `121`, not `CWE-121`.
- Explain rejected thesis candidates and why they must not appear in JSON.
- Explain any antithesis objections that were overruled and the evidence that supports overruling them.
- Keep claims concise and tied to inspected evidence.

Do not produce `vulnerabilities.json` in this stage.
"""

    run_prompt(agent, reconciliation_prompt, model=model)
    require_file(reconciliation_path, "crash reconciliation")

    final_prompt = f"""
{common_context}

Inputs:
- Evidence synthesis: `{synthesis_path}`
- Thesis: `{thesis_path}`
- Antithesis: `{antithesis_path}`
- Reconciliation: `{reconciliation_path}`

# Your task

Write exactly two final public artifacts:
1. `{vulnerabilities_path}`
2. `{report_path}`

`{vulnerabilities_path}` must be valid JSON with this exact top-level shape:

{{
  "vulnerabilities": [
    {{
      "cve-id": "CVE-<project-or-package>-00001",
      "cve-description": "...",
      "package-name": "...",
      "package-version": "...",
      "cwe-id": "...",
      "cwe-name": "...",
      "affected-function": "...",
      "affected-file": "...",
      "remediation-strategy": "exit"
    }}
  ]
}}

JSON rules:
- Use hyphenated keys exactly as shown, not snake_case.
- `vulnerabilities` must be an array.
- Include one entry per distinct reconciled root cause.
- If no credible vulnerability/root cause was identified, write exactly `{{"vulnerabilities":[]}}`.
- Include all required fields: `cve-id`, `cve-description`, `package-name`, `package-version`, `cwe-id`, `cwe-name`, `affected-function`, `affected-file`, and `remediation-strategy`. The `cwe-id` value must be the numeric string only, such as `121`, not `CWE-121`.
- Add `undesirable-function` only when the crash occurs inside a dangerous callee and the caller is the affected function.
- Do not include confidence scores, evidence blocks, comments, Markdown fences, trailing commas, or extra top-level keys in the JSON.

Field rules:
- Use `UNKNOWN` for package name or package version only if the crash artifacts and source tree do not provide enough evidence.
- `affected-function` must be the vulnerable/root-cause function, not merely `main`, a harness, a signal handler, libc, libstdc++, allocator, or sanitizer frame unless that really is the root cause.
- `affected-file` must be the project-relative source path containing `affected-function` when source is available.
- `cve-description` must be concise and include component/version, input condition, bug class, root cause, and crash/security impact.

CWE guidance:
- Put only the numeric portion in `cwe-id`; for example CWE-121 is encoded as `"cwe-id": "121"`.
- Use CWE-121 for stack-based buffer overflow / stack OOB.
- Use CWE-122 for heap-based buffer overflow.
- Use CWE-787 for out-of-bounds write.
- Use CWE-125 for out-of-bounds read.
- Use CWE-131 for incorrect buffer-size calculation.
- Use CWE-369 for divide by zero.
- Use CWE-190 for integer overflow.
- Use CWE-476 for null pointer dereference.
- Use CWE-590 for free of non-heap memory.
- Use CWE-119 only if the evidence shows memory corruption but the more specific class is unclear.

RESOLVE remediation guidance:
- Prefer `"remediation-strategy": "exit"` for generated crash reports unless there is clear evidence supporting another strategy.
- Use `"recover"` for memory corruption cases where continuing via recovery is intended.
- Use `"sat"` or `"widen"` only for integer overflow findings.
- Use `"continue"` for divide-by-zero or invalid operation masking only when continuing with a neutral value is appropriate.
- Use `"none"` only if the vulnerability should be recorded but not remediated.

`{report_path}` must be markdown. It should summarize the final vulnerability set, supporting evidence, rejected candidates, unresolved gaps, and any reproduction/debugger commands that materially influenced the final result.
"""

    run_prompt(agent, final_prompt, model=model)
    require_file(vulnerabilities_path, "final vulnerabilities.json")
    require_file(report_path, "final crash report")
    validate_vulnerabilities_json(vulnerabilities_path)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(
            agent=args.agent,
            crash_dir=args.crash_dir,
            source_dir=args.source_dir,
            output_path=args.output_path,
            overwrite=args.overwrite,
            model=args.model,
        )
    except subprocess.CalledProcessError as exc:
        print(f"agent failed with exit code {exc.returncode}")
        return exc.returncode if exc.returncode != 0 else 1
    except (RuntimeError, ValueError) as exc:
        print(exc)
        return -1


if __name__ == "__main__":
    raise SystemExit(main())
