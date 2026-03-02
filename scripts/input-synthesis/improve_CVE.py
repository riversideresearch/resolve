from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run an iterative CVE-improvement pipeline with a coding agent. "
            "All intermediate artifacts are written under a unique /tmp workspace "
            "and final results are copied to output_path."
        ),
        epilog=(
            "Examples:\n"
            "  python3 improve_CVE.py codex input/cve.json out/cve_run\n"
            "  python3 improve_CVE.py claude input/cve.json out/cve_run"
        ),
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
        help="Path to the input CVE JSON file used as the starting point.",
    )
    parser.add_argument(
        "output_path",
        type=Path,
        help=(
            "Destination directory for final artifacts copied from the temporary "
            "workspace."
        ),
    )
    return parser.parse_args(argv)


def run_agent(agent: str, prompt: str, fast: bool = False) -> None:
    if agent == "claude":
        agent_command = ["claude", "-p", "--dangerously-skip-permissions"]
    elif agent == "codex":
        agent_command = [
            "codex",
            "exec",
            "--config",
            'model_reasoning_effort="low"' if fast else 'model_reasoning_effort="high"',
            "--yolo",
            "--skip-git-repo-check",
        ]
    elif agent == "opencode":
        # agent_command = ["opencode", "run", "--model", "opencode/big-pickle"]
        agent_command = ["opencode", "run"]
    else:
        raise ValueError(f"unknown agent {agent=}")

    subprocess.run(agent_command + [prompt])


def run_prompt(agent: str, prompt: str, fast: bool = False) -> None:
    print(prompt)
    run_agent(agent, prompt, fast=fast)


def run_pipeline(
    agent: str,
    cve_path: Path,
    output_path: Path,
) -> int:
    with open(cve_path, "r") as f:
        original_cve = f.read()

    cve_name = str(cve_path.with_suffix("")).replace("/", "_")

    tmp_path = Path(tempfile.mkdtemp(dir="/tmp", prefix="improve_cve_"))
    print(f"Using temporary workspace: {tmp_path}")

    cve_tmp_path = tmp_path / cve_name
    cve_tmp_path.mkdir(parents=True, exist_ok=True)

    ################################################################################
    # FIRST PASS IMPROVEMENT
    ################################################################################

    cve_thesis_prompt = f"""
# CVE

{original_cve}

# Your task

The above CVE description is correct but possibly incomplete. Your task is to determine why it is correct. Write a report to `{cve_tmp_path}/thesis.md`.
"""
    run_prompt(agent, cve_thesis_prompt)

    cve_antithesis_prompt = f"""
# CVE

{original_cve}

# Your task

The above CVE description is incorrect. Your task is to determine why it is incorrect. Write a report to `{cve_tmp_path}/antithesis.md`.

Do not read any existing files under `{cve_tmp_path}` (especially `{cve_tmp_path}/thesis.md`). Only write your output to `{cve_tmp_path}/antithesis.md`.
"""
    run_prompt(agent, cve_antithesis_prompt)

    cve_synthesis_prompt = f"""
# CVE

{original_cve}

# Your task

`{cve_tmp_path}/thesis.md` and `{cve_tmp_path}/antithesis.md` contain possibly contradictory information about the above CVE. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{cve_tmp_path}/synthesis.md`.
"""
    run_prompt(agent, cve_synthesis_prompt)

    improved_cve_path = cve_tmp_path / "CVE.json"

    cve_improve_prompt = f"""
# CVE

{original_cve}

# Your task

`{cve_tmp_path}/synthesis.md` contains an analysis of the above CVE. Your task is to produce an improved version of the CVE in the same JSON format and save it to `{improved_cve_path}`. Don't add any additional fields to the JSON; use the exact same fields as the original. Don't include line numbers. Don't attempt to verify the CVE by performing additional analysis on the source code. Ensure that the scope of the improved CVE is the same as the original; it should address only the specific vulnerability described in the original. If the affected function name is a mangled C++ name, verify that it's exactly correct.

Match the tone and style of the original CVE description. Assume that there is a legitimate vulnerability, but it may not be exactly as described by the original. Keep particular details to a minimum; just describe the nature of the vulnerability and conditions for causing it.
"""
    run_prompt(agent, cve_improve_prompt)

    ################################################################################
    # NECESSARY CONDITION INFERENCE
    ################################################################################

    necessary_conditions_path = cve_tmp_path / "necessary_conditions"
    necessary_conditions_path.mkdir(parents=True, exist_ok=True)

    necessary_conditions_prompt = f"""
`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

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

    run_prompt(agent, necessary_conditions_prompt)

    ################################################################################
    # NECESSARY CONDITION WEAKENING
    ################################################################################

    revised_necessary_conditions_path = cve_tmp_path / "necessary_conditions_revised"
    revised_necessary_conditions_path.mkdir(parents=True, exist_ok=True)

    necessary_condition_paths = [p for p in necessary_conditions_path.iterdir() if p.is_file()]
    for p in necessary_condition_paths:
        with open(p, "r") as f:
            condition = f.read()
        revised_condition_path = revised_necessary_conditions_path / p.name
        p_tmp = necessary_conditions_path / (p.stem + "_tmp")
        p_tmp.mkdir(parents=True, exist_ok=True)

        necessary_condition_thesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

The condition given above is a necessary condition. I.e., there is no way to trigger the bug without satisfying the condition. Your task is to determine why. Write a report to `{p_tmp}/thesis.md`.

Don't look at existing thesis documents.
"""
        run_prompt(agent, necessary_condition_thesis_prompt)

        necessary_condition_antithesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

The condition given above is not a necessary condition. I.e., there is some way to trigger the bug without satisfying the condition. Your task is to determine how. Write a report to `{p_tmp}/antithesis.md`.

Do not read any existing files under `{p_tmp}` (especially `{p_tmp}/thesis.md`). Only write your output to `{p_tmp}/antithesis.md`.
"""
        run_prompt(agent, necessary_condition_antithesis_prompt)

        necessary_condition_synthesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

`{p_tmp}/thesis.md` and `{p_tmp}/antithesis.md` contain possibly contradictory information about the above condition. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{p_tmp}/synthesis.md`.

Don't look at existing synthesis documents.
"""
        run_prompt(agent, necessary_condition_synthesis_prompt)

        necessary_condition_improve_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

`{p_tmp}/synthesis.md` contains an analysis of the above condition. Your task:
- If the analysis concludes that the condition is necessary or that it can be modified to be necessary, produce an improved version of the necessary condition description and save it to `{revised_condition_path}`.
- If the analysis concludes that the condition is not necessary and doesn't provide a way to modify it to make it necessary, do nothing.
Do not write any files other than `{revised_condition_path}`.
"""
        run_prompt(agent, necessary_condition_improve_prompt)

    ################################################################################
    # SUFFICIENT CONDITION INFERENCE
    ################################################################################

    sufficient_conditions_path = cve_tmp_path / "sufficient_conditions"
    sufficient_conditions_path.mkdir(parents=True, exist_ok=True)

    sufficient_conditions_prompt = f"""
`{cve_path}` describes a CVE. `{improved_cve_path}` is a derived description that may provide more detail. The files in `{revised_necessary_conditions_path}/` describe a conjunctive collection (all must be true) of necessary conditions for triggering the CVE.

A condition is "necessary" if there is no way to trigger the bug without satisfying the condition. I.e., if the bug is triggered, the condition must be true. A condition is "sufficient" if satisfying the condition guarantees that the bug will be triggered.

Your task is to determine a disjunctive (either/or) list of sufficient conditions for triggering the CVE. Write a concise report for each sufficient condition and store each one in `{sufficient_conditions_path}/` in a separate markdown file.

Create exactly one markdown file per sufficient condition, named `SC_1.md`, `SC_2.md`, etc. Write only those `SC_*.md` files in `{sufficient_conditions_path}/`.
"""
    run_prompt(agent, sufficient_conditions_prompt)

    ################################################################################
    # SUFFICIENT CONDITION STRENGTHENING
    ################################################################################

    revised_sufficient_conditions_path = cve_tmp_path / "sufficient_conditions_revised"
    revised_sufficient_conditions_path.mkdir(parents=True, exist_ok=True)

    sufficient_condition_paths = [p for p in sufficient_conditions_path.iterdir() if p.is_file()]
    for p in sufficient_condition_paths:
        with open(p, "r") as f:
            condition = f.read()
        revised_condition_path = revised_sufficient_conditions_path / p.name
        p_tmp = sufficient_conditions_path / (p.stem + "_tmp")
        p_tmp.mkdir(parents=True, exist_ok=True)

        sufficient_condition_thesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

The condition given above is a sufficient condition. I.e., if the condition is satisfied the bug is guaranteed to trigger. Your task is to determine why. Write a report to `{p_tmp}/thesis.md`.

Don't look at existing thesis documents.
"""
        run_prompt(agent, sufficient_condition_thesis_prompt)

        sufficient_condition_antithesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

The condition given above is not a sufficient condition. I.e., there is some way to satisfy the condition without triggering the bug. Your task is to determine how. Write a report to `{p_tmp}/antithesis.md`.

Do not read any existing files under `{p_tmp}` (especially `{p_tmp}/thesis.md`). Only write your output to `{p_tmp}/antithesis.md`.
"""
        run_prompt(agent, sufficient_condition_antithesis_prompt)

        sufficient_condition_synthesis_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

`{p_tmp}/thesis.md` and `{p_tmp}/antithesis.md` contain possibly contradictory information about the above condition. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{p_tmp}/synthesis.md`.

Don't look at existing synthesis documents.
"""
        run_prompt(agent, sufficient_condition_synthesis_prompt)

        sufficient_condition_improve_prompt = f"""
# CVE

`{cve_path}` describes a CVE affecting this project. `{improved_cve_path}` is a derived description that may provide more detail.

# Condition

{condition}

# Your task

`{p_tmp}/synthesis.md` contains an analysis of the above condition. Your task:
- If the analysis concludes that the condition is sufficient or that it can be modified to be sufficient, produce an improved version of the sufficient condition description and save it to `{revised_condition_path}`.
- If the analysis concludes that the condition is not sufficient and doesn't provide a way to modify it to make it sufficient, do nothing.
Do not write any files other than `{revised_condition_path}`.
"""
        run_prompt(agent, sufficient_condition_improve_prompt)

    ################################################################################
    # COPY FINAL RESULTS TO OUTPUT PATH
    ################################################################################

    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(cve_tmp_path, output_path, dirs_exist_ok=True)

    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run_pipeline(
            agent=args.agent,
            cve_path=args.cve_path,
            output_path=args.output_path,
        )
    except ValueError as exc:
        print(exc)
        return -1


if __name__ == "__main__":
    raise SystemExit(main())
