// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{Context, Result};
use clap::Parser;
use resolve_cli::{Agent, run_prompt};
use std::path::PathBuf;

const SETUP_PROMPT_TEMPLATE: &str = include_str!("../../prompts/input-synthesis-setup.txt");

#[derive(Parser)]
#[command(
    name = "resolve-input-synthesis-setup",
    about = "Prepare a target project for CVE analysis: check out the affected version, map architecture, install dependencies, and build.",
    after_help = "Examples:\n  resolve-input-synthesis-setup claude cve.json\n  resolve-input-synthesis-setup codex cve.json"
)]
struct Args {
    /// Coding agent backend to execute prompts with
    #[arg(value_parser = ["claude", "codex", "opencode"])]
    agent: String,

    /// Path to the input CVE file
    cve_path: PathBuf,

    /// Optional model override passed through to the selected agent CLI
    #[arg(long)]
    model: Option<String>,
}

fn run(args: Args) -> Result<()> {
    let agent = Agent::from_str(&args.agent)?;
    let agents_file = agent.agents_file();

    let cve_path = args.cve_path.canonicalize()
        .with_context(|| format!("Failed to resolve CVE path: {}", args.cve_path.display()))?;

    let setup_prompt = SETUP_PROMPT_TEMPLATE
        .replace("{CVE_PATH}", &cve_path.display().to_string())
        .replace("{AGENTS_FILE}", agents_file);

    run_prompt(agent, &setup_prompt, args.model.as_deref())?;

    Ok(())
}

fn main() {
    let args = Args::parse();
    
    if let Err(e) = run(args) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
