# Copyright (c) 2025-2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import subprocess
import sys
from pathlib import Path

from resolve.agent_utils.agent import AGENTS_FILE, run_prompt
from resolve.agent_utils.utils import prepare_output_path, require_file


def synthesis_prompt_from_reachability(reachability_path: Path, output_path: Path) -> str:
    """Prompt used when a prior reachability analysis exists (full pipeline)."""
    return f"""
`{reachability_path}` contains a reachability analysis of a CVE possibly affecting this project. Your tasks:
1) If `{reachability_path}` concludes that the CVE is reachable or triggerable, synthesize an input that triggers it and verify that it works. If triggerability is inconclusive, try to synthesize an input and see if it works (and if it fails still report the result as inconclusive). If `{reachability_path}` concludes that the CVE is not triggerable, skip this step. Don't second-guess the conclusion.
2) Write a one-paragraph summary of the conclusion to `{output_path}/conclusion.md`.

If you synthesize an input, ensure that it will work on any realistic system if possible. E.g., if the exploit depends on resource exhaustion then make it work on a system that has a large amount of that resource.

Put any files you create in `{output_path}/input-synthesis/`. If a triggering input is synthesized, include an explanation of how it was synthesized and how to test that it works. Don't delete any scripts/programs that were used to generate the input.
"""


def synthesis_prompt_from_cve(cve: str, output_path: Path, agents_file: str) -> str:
    """Prompt used for standalone synthesis directly from a CVE (no reachability report)."""
    return f"""
# CVE

{cve}

# Your task

The above CVE describes a vulnerability in this project. Skip reachability analysis; assume the vulnerability is present and attempt to synthesize a concrete input that triggers it, then verify that it actually triggers.

1) Synthesize an input that triggers the described vulnerability against the target in this working directory. If `{agents_file}` exists it describes how the project is built and run and where the build artifacts (e.g. a prebuilt target binary) live; use it. If a build artifact is not already present, build the target as `{agents_file}` describes.
2) Verify the input by running it against the actual built/dockerized target and observing the failure directly (e.g. a segfault / `exited with status 139` for a memory-safety bug, or a sanitizer report). Do not claim success from static reasoning alone — a synthesized input only counts if the target actually crashes/faults when fed the input.
3) Write a one-paragraph summary of the conclusion to `{output_path}/conclusion.md`. State plainly whether you produced a verified triggering input, and if not, why (e.g. the input was rejected before reaching the vulnerable code, or the crash could not be reproduced) and report the result as inconclusive.

Do not modify the vulnerable target or any provided test harness to make the input work; the input itself must be what triggers the bug. If your trigger is unreliable, fix the driver/generation logic, not the target.

If you synthesize an input, ensure that it will work on any realistic system if possible. E.g., if the exploit depends on resource exhaustion then make it work on a system that has a large amount of that resource.

Put any files you create in `{output_path}/input-synthesis/`. If a triggering input is synthesized, include an explanation of how it was synthesized and how to test that it works. Don't delete any scripts/programs that were used to generate the input.
"""


def run_synthesis(agent: str, prompt: str, output_path: Path, model: str | None) -> None:
    """Shared synthesis primitive: run the prompt and require a conclusion.

    Callers are responsible for preparing `output_path`. This is intentionally
    kept separate from `prepare_output_path` so the reachability pipeline can
    reuse an output directory it has already populated (with reachability.md)
    without clobbering it.
    """
    run_prompt(agent, prompt, model=model)
    require_file(output_path / "conclusion.md", "final conclusion")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    prog = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description="Synthesize and verify a triggering input for a CVE directly from its description, "
        "without running the improve-CVE/reachability reasoning stages. Intended for lightweight cases "
        "where the vulnerability is already well understood and the target is available to run.",
        epilog=f"""Examples:
  {prog} claude cve.json out/synthesize
  {prog} codex cve.json out/synthesize --overwrite""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "agent",
        choices=("claude", "codex", "opencode"),
        help="Coding agent backend to execute prompts with.",
    )
    parser.add_argument(
        "cve_path",
        type=Path,
        help="Path to the input CVE file.",
    )
    parser.add_argument(
        "output_path",
        type=Path,
        help="Destination directory for conclusion.md and input-synthesis/ artifacts.",
    )
    parser.add_argument(
        "--model",
        help="Optional model override passed through to the selected agent CLI.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output_path if it already exists.",
    )
    return parser.parse_args(argv)


def run(
    agent: str,
    cve_path: Path,
    output_path: Path,
    overwrite: bool,
    model: str | None = None,
) -> int:
    cve = cve_path.read_text()

    prepare_output_path(output_path, overwrite)
    output_path.mkdir(parents=True, exist_ok=True)

    prompt = synthesis_prompt_from_cve(cve, output_path, AGENTS_FILE[agent])
    run_synthesis(agent, prompt, output_path, model)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(
            agent=args.agent,
            cve_path=args.cve_path,
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
