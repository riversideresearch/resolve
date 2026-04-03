# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import json
import os
import subprocess
from pathlib import Path


def run_agent(
    agent: str,
    prompt: str,
    fast: bool = False,
    model: str | None = None,
) -> None:
    env = os.environ.copy()
    match agent.lower():
      case "claude":
        agent_command = ["claude", "-p", "--dangerously-skip-permissions"]
        if model is not None:
            agent_command.extend(["--model", model])
      case "codex":
        agent_command = [
            "codex",
            "exec",
            "--config",
            'model_reasoning_effort="low"' if fast else 'model_reasoning_effort="high"',
            "--yolo",
            "--skip-git-repo-check",
        ]
        if model is not None:
            agent_command.extend(["--model", model])
      case "opencode":
        env["OPENCODE_PERMISSION"] = json.dumps({"*": "allow"})
        agent_command = ["opencode", "run", "--agent", "build"]
        if model is not None:
            agent_command.extend(["--model", model])
      case _:
        raise ValueError(f"unknown agent {agent=}")

    subprocess.run(agent_command + [prompt], env=env, check=True)


def run_prompt(
    agent: str,
    prompt: str,
    fast: bool = False,
    model: str | None = None,
) -> None:
    print(prompt)
    run_agent(agent, prompt, fast=fast, model=model)


def run_dialectic(
    agent: str,
    preamble: str,
    affirmation: str,
    negation: str,
    tmp_dir: Path,
    model: str | None = None,
) -> None:
    """Run a MAD-like debate and write the results to tmp_dir."""
    thesis_prompt = f"""
{preamble}

# Your task

{affirmation} Write a report to `{tmp_dir}/thesis.md`.

Don't look at existing thesis documents.
"""
    run_prompt(agent, thesis_prompt, model=model)

    antithesis_prompt = f"""
{preamble}

# Your task

{negation} Write a report to `{tmp_dir}/antithesis.md`.

Do not read any existing files under `{tmp_dir}` (especially `{tmp_dir}/thesis.md`). Only write your output to `{tmp_dir}/antithesis.md`.
"""
    run_prompt(agent, antithesis_prompt, model=model)

    synthesis_prompt = f"""
{preamble}

# Your task

`{tmp_dir}/thesis.md` and `{tmp_dir}/antithesis.md` contain possibly contradictory information. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{tmp_dir}/synthesis.md`.

Don't look at existing synthesis documents.
"""
    run_prompt(agent, synthesis_prompt, model=model)


def run_critique(
    agent: str,
    preamble: str,
    negation: str,
    tmp_dir: Path,
    output_path: Path,
    model: str | None = None,
) -> None:
    """Run a challenge-and-revise loop on an existing claim and write the revision to output_path."""
    critique_prompt = f"""
{preamble}

# Your task

{negation} Write a report to `{tmp_dir}/critique.md`.
"""
    run_prompt(agent, critique_prompt, model=model)

    improve_prompt = f"""
{preamble}

# Your task

`{tmp_dir}/critique.md` contains a critique of the above. Determine which points in the critique are valid and produce an improved version that addresses them. Save the result to `{output_path}`.
"""
    run_prompt(agent, improve_prompt, model=model)
