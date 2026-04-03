# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .agent import run_critique, run_dialectic, run_prompt
from .utils import prepare_output_path, require_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    prog = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description="Run a CVE-improvement pipeline with a coding agent. The pipeline uses a debate pass plus challenge/revise passes. All intermediate artifacts are written under a unique /tmp workspace and final results are copied to output_path.",
        epilog=f"""Examples:
  {prog} codex cve.json out/improve_cve
  {prog} claude cve.json out/improve_cve""",
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
        help="Path to the input CVE file used as the starting point.",
    )
    parser.add_argument(
        "output_path",
        type=Path,
        help="Destination directory for final artifacts copied from the temporary workspace.",
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


def list_condition_files(path: Path, role: str) -> list[Path]:
    pattern = "NC_*.md" if role == "necessary" else "SC_*.md"
    return sorted(p for p in path.glob(pattern) if p.is_file())


def refine_conditions(
    agent: str,
    cve_preamble: str,
    source_dir: Path,
    dest_dir: Path,
    scratch_root: Path,
    role: str,
    model: str | None,
) -> None:
    """Challenge each condition in source_dir and write any revised versions to dest_dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    if role == "necessary":
        negation = "The condition given above is not a necessary condition. I.e., there is some way to trigger the bug without satisfying the condition. Your task is to determine how."
    elif role == "sufficient":
        negation = "The condition given above is not a sufficient condition. I.e., there is some way to satisfy the condition without triggering the bug. Your task is to determine how."
    else:
        raise ValueError(f"unknown {role=}")

    condition_files = list_condition_files(source_dir, role)
    if not condition_files:
        print(f"warning: no {role} condition files found in {source_dir}")
        return

    for p in condition_files:
        condition = p.read_text()
        revised_condition_path = dest_dir / p.name
        p_tmp = scratch_root / role / p.stem
        p_tmp.mkdir(parents=True, exist_ok=True)

        preamble = f"""{cve_preamble}

# Condition

{condition}"""

        run_critique(
            agent,
            preamble,
            negation,
            p_tmp,
            revised_condition_path,
            model=model,
        )
        require_file(revised_condition_path, f"{role} condition refinement for {p.name}")


def run(
    agent: str,
    cve_path: Path,
    output_path: Path,
    overwrite: bool,
    model: str | None = None,
) -> int:
    original_cve = cve_path.read_text()
    cve_name = str(cve_path.with_suffix("")).replace("/", "_")

    prepare_output_path(output_path, overwrite)

    tmp_path = Path(tempfile.mkdtemp(dir="/tmp", prefix="improve_cve_"))
    print(f"Using temporary workspace: {tmp_path}")

    cve_tmp_path = tmp_path / cve_name
    cve_tmp_path.mkdir(parents=True, exist_ok=True)
    scratch_root = tmp_path / "critique_scratch"

    ############################################################################
    # FIRST PASS IMPROVEMENT
    ############################################################################

    cve_preamble = f"# CVE\n\n{original_cve}"

    run_dialectic(
        agent,
        preamble=cve_preamble,
        affirmation="The above CVE description is correct but possibly incomplete. Your task is to determine why it is correct.",
        negation="The above CVE description is incorrect. Your task is to determine why it is incorrect.",
        tmp_dir=cve_tmp_path,
        model=model,
    )
    require_file(cve_tmp_path / "thesis.md", "CVE dialectic thesis")
    require_file(cve_tmp_path / "antithesis.md", "CVE dialectic antithesis")
    require_file(cve_tmp_path / "synthesis.md", "CVE dialectic synthesis")

    improved_cve_path = cve_tmp_path / cve_path.name

    cve_improve_prompt = f"""
{cve_preamble}

# Your task

`{cve_tmp_path}/synthesis.md` contains an analysis of the above CVE. Your task is to produce an improved version of the CVE in the same format and save it to `{improved_cve_path}`. Use the exact same structure and fields as the original. Don't include line numbers. Don't attempt to verify the CVE by performing additional analysis on the source code. Ensure that the scope of the improved CVE is the same as the original; it should address only the specific vulnerability described in the original. If the affected function name is a mangled C++ name, verify that it's exactly correct.

Match the tone and style of the original CVE description. Assume that there is a legitimate vulnerability, but it may not be exactly as described by the original. Keep particular details to a minimum; just describe the nature of the vulnerability and conditions for causing it.
"""
    run_prompt(agent, cve_improve_prompt, model=model)
    require_file(improved_cve_path, "CVE improvement")

    ############################################################################
    # NECESSARY CONDITION INFERENCE
    ############################################################################

    necessary_conditions_path = cve_tmp_path / "necessary_conditions"
    necessary_conditions_path.mkdir(parents=True, exist_ok=True)

    condition_preamble = f"# CVE\n\n`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail."

    necessary_conditions_prompt = f"""
{condition_preamble}

Your task is to determine a conjunctive list (all must be true) of necessary conditions for triggering the CVE. Write a concise report for each necessary condition and store each one in `{necessary_conditions_path}/` in a separate markdown file.

Create exactly one markdown file per necessary condition, named `NC_1.md`, `NC_2.md`, etc. Write only those `NC_*.md` files in `{necessary_conditions_path}/`.

A condition is "necessary" if there is no way to trigger the bug without satisfying the condition. I.e., if the bug is triggered, the condition must be true.

Be extremely careful with necessary conditions; they should be absolutely (not probably, "practically", "typically") valid judgements, and should be simple statements of definite conditions without additional speculation about what causes them.

If a necessary condition involves arithmetic or bit shifting, provide only the general condition. E.g., "this expression must be greater than 0" with no additional details about what would cause the expression to be greater than 0.

Verify that the necessary conditions are truly necessary, not just sufficient. A condition is "sufficient" if satisfying the condition guarantees that the bug will be triggered.
"""

    # TODO: maybe be more strict in the above prompt in the "be extremely
    # careful" paragraph. Something like "just state the general condition
    # and don't include further elaboration like 'this happens when ...'.

    run_prompt(agent, necessary_conditions_prompt, model=model)

    ############################################################################
    # NECESSARY CONDITION WEAKENING
    ############################################################################

    revised_necessary_conditions_path = cve_tmp_path / "necessary_conditions_revised"

    refine_conditions(
        agent,
        cve_preamble=condition_preamble,
        source_dir=necessary_conditions_path,
        dest_dir=revised_necessary_conditions_path,
        scratch_root=scratch_root,
        role="necessary",
        model=model,
    )

    ############################################################################
    # SUFFICIENT CONDITION INFERENCE
    ############################################################################

    sufficient_conditions_path = cve_tmp_path / "sufficient_conditions"
    sufficient_conditions_path.mkdir(parents=True, exist_ok=True)

    sufficient_conditions_prompt = f"""
`{cve_path}` describes a CVE. `{improved_cve_path}` is a derived description that may provide more detail. The files in `{revised_necessary_conditions_path}/` describe a conjunctive collection (all must be true) of necessary conditions for triggering the CVE.

A condition is "necessary" if there is no way to trigger the bug without satisfying the condition. I.e., if the bug is triggered, the condition must be true. A condition is "sufficient" if satisfying the condition guarantees that the bug will be triggered.

Your task is to determine a disjunctive (either/or) list of sufficient conditions for triggering the CVE. Write a concise report for each sufficient condition and store each one in `{sufficient_conditions_path}/` in a separate markdown file.

Create exactly one markdown file per sufficient condition, named `SC_1.md`, `SC_2.md`, etc. Write only those `SC_*.md` files in `{sufficient_conditions_path}/`.
"""
    run_prompt(agent, sufficient_conditions_prompt, model=model)

    ############################################################################
    # SUFFICIENT CONDITION STRENGTHENING
    ############################################################################

    revised_sufficient_conditions_path = cve_tmp_path / "sufficient_conditions_revised"

    refine_conditions(
        agent,
        cve_preamble=condition_preamble,
        source_dir=sufficient_conditions_path,
        dest_dir=revised_sufficient_conditions_path,
        scratch_root=scratch_root,
        role="sufficient",
        model=model,
    )

    ############################################################################
    # COPY FINAL RESULTS TO OUTPUT PATH
    ############################################################################

    output_path.mkdir(parents=True, exist_ok=False)

    shutil.copy(improved_cve_path, output_path / improved_cve_path.name)
    shutil.copytree(
        revised_necessary_conditions_path,
        output_path / "necessary_conditions",
    )
    shutil.copytree(
        revised_sufficient_conditions_path,
        output_path / "sufficient_conditions",
    )

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
