import subprocess
from pathlib import Path


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

    subprocess.run(agent_command + [prompt], check=True)


def run_prompt(agent: str, prompt: str, fast: bool = False) -> None:
    print(prompt)
    run_agent(agent, prompt, fast=fast)


def run_dialectic(
    agent: str,
    preamble: str,
    affirmation: str,
    negation: str,
    tmp_dir: Path,
) -> None:
    """Run a thesis/antithesis/synthesis dialectic, writing results to tmp_dir."""
    thesis_prompt = f"""
{preamble}

# Your task

{affirmation} Write a report to `{tmp_dir}/thesis.md`.

Don't look at existing thesis documents.
"""
    run_prompt(agent, thesis_prompt)

    antithesis_prompt = f"""
{preamble}

# Your task

{negation} Write a report to `{tmp_dir}/antithesis.md`.

Do not read any existing files under `{tmp_dir}` (especially `{tmp_dir}/thesis.md`). Only write your output to `{tmp_dir}/antithesis.md`.
"""
    run_prompt(agent, antithesis_prompt)

    synthesis_prompt = f"""
{preamble}

# Your task

`{tmp_dir}/thesis.md` and `{tmp_dir}/antithesis.md` contain possibly contradictory information. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{tmp_dir}/synthesis.md`.

Don't look at existing synthesis documents.
"""
    run_prompt(agent, synthesis_prompt)


def run_critique(
    agent: str,
    preamble: str,
    negation: str,
    tmp_dir: Path,
    output_path: Path,
) -> None:
    """Critique an existing claim (the preamble) and produce an improved version at output_path."""
    critique_prompt = f"""
{preamble}

# Your task

{negation} Write a report to `{tmp_dir}/critique.md`.
"""
    run_prompt(agent, critique_prompt)

    improve_prompt = f"""
{preamble}

# Your task

`{tmp_dir}/critique.md` contains a critique of the above. Determine which points in the critique are valid and produce an improved version that addresses them. Save the result to `{output_path}`.
"""
    run_prompt(agent, improve_prompt)
