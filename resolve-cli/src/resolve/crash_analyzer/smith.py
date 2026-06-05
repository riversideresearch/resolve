# Copyright (c) 2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import subprocess
import sys
from pathlib import Path

import __main__

from resolve.agent_utils.agent import run_prompt, AGENTS_FILE
from resolve.agent_utils.utils import prepare_output_path, require_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    prog = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description="Generate a CVE report given crashing conditions.",
        epilog=f"""Examples:
  {prog} claude -o cve.json
  {prog} codex -i crash_dir
  {prog} codex -i crash_dir -s source_dir""",
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
        help="Destination directory for final artifacts copied from the temporary workspace.",
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


def run(agent: str, crash_dir: Path, source_dir: Path | None, output_path: Path, overwrite: bool, model: str | None = None) -> int:
    agents_file = AGENTS_FILE[agent]

    prepare_output_path(output_path, overwrite)

    tmp_path = output_path / "tmp"
    tmp_path.mkdir(parents=True, exist_ok=True)
    print(f"Using temporary workspace: {tmp_path}")

    synthesis_prompt = f"""
# CVE

`{crash_dir}` contains a folder with information and artifacts regarding a crash in an unspecified program.

# Your task

Do the following:
1) Explore key artifacts (like coredumps) and triage the crash, identifying the root cause if possible.
2) If applicable, update `{agents_file}` with any relevant findings, insights, or quirks that would be relevant for other agents.
3) Use tools like `gdb` to investigate coredumps and other artifacts{", read source code in " + str(source_dir) if source_dir is not None else ""}.
4) Create {tmp_path / "synthesis.md"}: An objective (no assumptions may be made, whatsoever) aggregation of ALL important facts and evidence uncovered from thorough investigation of the artifacts.

"""
    # 2) If source code is provided and it is trivial to do so, you can attempt to rebuild the program

    run_prompt(agent, synthesis_prompt, model=model)

    require_file(tmp_path / "synthesis.md", "synthesis")

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(agent=args.agent, crash_dir=args.crash_dir, source_dir=args.source_dir, output_path=args.output_path, overwrite=args.overwrite, model=args.model)
    except subprocess.CalledProcessError as exc:
        print(f"agent failed with exit code {exc.returncode}")
        return exc.returncode if exc.returncode != 0 else 1
    except ValueError as exc:
        print(exc)
        return -1


if __name__ == "__main__":
    raise SystemExit(main())
