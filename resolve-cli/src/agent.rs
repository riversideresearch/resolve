// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy)]
pub enum Agent {
    Claude,
    Codex,
    Opencode,
}

impl Agent {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "opencode" => Ok(Self::Opencode),
            _ => bail!("Unknown agent: {}", s),
        }
    }
    
    pub fn agents_file(&self) -> &'static str {
        match self {
            Agent::Claude => "CLAUDE.md",
            Agent::Codex => "AGENTS.md",
            Agent::Opencode => "AGENTS.md",
        }
    }
}

pub fn run_agent(agent: Agent, prompt: &str, model: Option<&str>) -> Result<()> {
    let mut cmd = match agent {
        Agent::Claude => {
            let mut cmd = Command::new("claude");
            cmd.args(["-p", "--dangerously-skip-permissions"]);
            if let Some(m) = model {
                cmd.args(["--model", m]);
            }
            cmd
        }
        Agent::Codex => {
            let mut cmd = Command::new("codex");
            cmd.args([
                "exec",
                "--config",
                "model_reasoning_effort=\"high\"",
                "--yolo",
                "--skip-git-repo-check",
            ]);
            if let Some(m) = model {
                cmd.args(["--model", m]);
            }
            cmd
        }
        Agent::Opencode => {
            let mut cmd = Command::new("opencode");
            cmd.env("OPENCODE_PERMISSION", r#"{"*":"allow"}"#);
            cmd.args(["run", "--agent", "build"]);
            if let Some(m) = model {
                cmd.args(["--model", m]);
            }
            cmd
        }
    };
    
    cmd.arg(prompt);
    
    let status = cmd.status().context("Failed to run agent")?;
    if !status.success() {
        bail!("Agent exited with status {}", status);
    }
    
    Ok(())
}

pub fn run_prompt(agent: Agent, prompt: &str, model: Option<&str>) -> Result<()> {
    println!("{}", prompt);
    run_agent(agent, prompt, model)
}

/// Run a MAD-like debate and write the results to tmp_dir.
pub fn run_dialectic(
    agent: Agent,
    preamble: &str,
    affirmation: &str,
    negation: &str,
    tmp_dir: &Path,
    model: Option<&str>,
) -> Result<()> {
    let thesis_prompt = format!(
        "{}\n\n# Your task\n\n{} Write a report to `{}/thesis.md`.\n\nDon't look at existing thesis documents.",
        preamble,
        affirmation,
        tmp_dir.display()
    );
    run_prompt(agent, &thesis_prompt, model)?;

    let antithesis_prompt = format!(
        "{}\n\n# Your task\n\n{} Write a report to `{}/antithesis.md`.\n\nDo not read any existing files under `{}` (especially `{}/thesis.md`). Only write your output to `{}/antithesis.md`.",
        preamble,
        negation,
        tmp_dir.display(),
        tmp_dir.display(),
        tmp_dir.display(),
        tmp_dir.display()
    );
    run_prompt(agent, &antithesis_prompt, model)?;

    let synthesis_prompt = format!(
        "{}\n\n# Your task\n\n`{}/thesis.md` and `{}/antithesis.md` contain possibly contradictory information. Your task is to resolve any contradictions and form a final conclusion. Save a report to `{}/synthesis.md`.\n\nDon't look at existing synthesis documents.",
        preamble,
        tmp_dir.display(),
        tmp_dir.display(),
        tmp_dir.display()
    );
    run_prompt(agent, &synthesis_prompt, model)?;

    Ok(())
}

/// Run a challenge-and-revise loop on an existing claim and write the revision to output_path.
pub fn run_critique(
    agent: Agent,
    preamble: &str,
    negation: &str,
    tmp_dir: &Path,
    output_path: &Path,
    model: Option<&str>,
) -> Result<()> {
    let critique_prompt = format!(
        "{}\n\n# Your task\n\n{} Write a report to `{}/critique.md`.",
        preamble,
        negation,
        tmp_dir.display()
    );
    run_prompt(agent, &critique_prompt, model)?;

    let improve_prompt = format!(
        "{}\n\n# Your task\n\n`{}/critique.md` contains a critique of the above. Determine which points in the critique are valid and produce an improved version that addresses them. Save the result to `{}`.",
        preamble,
        tmp_dir.display(),
        output_path.display()
    );
    run_prompt(agent, &improve_prompt, model)?;

    Ok(())
}
