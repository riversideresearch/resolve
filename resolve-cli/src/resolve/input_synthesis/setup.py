# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import subprocess
import sys
from pathlib import Path

import __main__

from .agent import run_prompt

AGENTS_FILE = {
    "claude": "CLAUDE.md",
    "codex": "AGENTS.md",
    "opencode": "AGENTS.md",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    prog = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description="Prepare a target project for CVE analysis: check out the affected version, map architecture, install dependencies, and build.",
        epilog=f"""Examples:
  {prog} claude cve.json
  {prog} codex cve.json""",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "agent",
        choices=("claude", "codex", "opencode"),
        help="Coding agent backend to execute prompts with.",
    )
    # parser.add_argument(
    #     "cve_path",
    #     type=Path,
    #     help="Path to the input CVE file.",
    # )
    parser.add_argument(
        "--model",
        help="Optional model override passed through to the selected agent CLI.",
    )
    return parser.parse_args(argv)


def run(agent: str,
        # cve_path: Path,
        model: str | None = None) -> int:
    agents_file = AGENTS_FILE[agent]

#     setup_prompt = f"""
# # CVE

# `{cve_path}` contains a description of a CVE affecting this project.

# # Your task

# Do the following:
# 1) Map the project architecture, dependencies, and build instructions and save them to `{agents_file}`.
# 2) Install the project dependencies. Ensure that the source code for all dependencies is available locally (not just pre-built binaries), so that subsequent analysis can inspect it.
# 3) Build the project. Put build artifacts in a `build/` directory.
# 4) Update `{agents_file}` if necessary to account for any issues encountered when installing deps and building the project.
# """

#     setup_prompt = f"""
# # Your task

# Do the following:
# 1) Map the project architecture, dependencies, and build instructions and save them to `{agents_file}`. Keep it brief and concise.
# 2) Install the project dependencies. Ensure that the source code for all dependencies is available locally (not just pre-built binaries), so that subsequent analysis can inspect it.
# 3) Build the project. Put build artifacts in a `build/` directory.
# 4) Update `{agents_file}` with local build instructions. Remember to keep it brief.
# 5) If you encountered any issues when installing deps and building the project, describe them in `build-issues.md`.
# """

    setup_prompt = f"""
# Your task

1) Read `README.md` if it exists. Map the project architecture, dependencies, and build instructions and save them along with a summary overview of the repo to `{agents_file}`. Keep it brief and concise.
2) Figure out how to do a local build in `build/`. Ensure source code is available for vcpkg dependencies, not just pre-built binaries. Ensure that the poller script works as expected against the local build and that we can test PoVs against it. Ensure that the local build uses the same versions of all dependencies as the Docker build. Save local build instructions to `local-build.md`. Add pointers in `{agents_file}` to `local-build.md` and the location of dependencies' source code.
"""

#     setup_prompt = f"""
# # Your task

# 1) Read `README.md` if it exists. Map the project architecture, dependencies, and build instructions and save them along with a summary overview of the repo to `{agents_file}`. Keep it brief and concise.
# 2) Ensure source code is available for all of the application's dependencies. Some of them may be vendored, in which case we don't have to do anything. Others may be pulled down using vcpkg or something similar; in those cases pull down their source code (not just pre-built binaries) to a local location. Add a pointer in `{agents_file}` to the location(s) of dependencies' source code.
# """

    run_prompt(agent, setup_prompt, model=model)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run(agent=args.agent,
                   # cve_path=args.cve_path,
                   model=args.model)
    except subprocess.CalledProcessError as exc:
        print(f"agent failed with exit code {exc.returncode}")
        return exc.returncode if exc.returncode != 0 else 1
    except ValueError as exc:
        print(exc)
        return -1


if __name__ == "__main__":
    raise SystemExit(main())
