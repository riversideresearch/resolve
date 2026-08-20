// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{Context, Result};
use clap::Parser;
use resolve_cli::{Agent, run_prompt, prepare_output_path, require_file};
use std::fs;
use std::path::PathBuf;

const SYNTHESIS_FROM_CVE_TEMPLATE: &str = include_str!("../../prompts/input-synthesis-synthesis-from-cve.txt");

#[derive(Parser)]
#[command(
    name = "resolve-input-synthesis-synthesize",
    about = "Synthesize and verify a triggering input for a CVE directly from its description, \
             without running the improve-CVE/reachability reasoning stages. Intended for lightweight cases \
             where the vulnerability is already well understood and the target is available to run.",
    after_help = "Examples:\n  resolve-input-synthesis-synthesize claude cve.json out/synthesize\n  resolve-input-synthesis-synthesize codex cve.json out/synthesize --overwrite"
)]
struct Args {
    /// Coding agent backend to execute prompts with
    #[arg(value_parser = ["claude", "codex", "opencode"])]
    agent: String,

    /// Path to the input CVE file
    cve_path: PathBuf,

    /// Destination directory for conclusion.md and input-synthesis/ artifacts
    output_path: PathBuf,

    /// Optional model override passed through to the selected agent CLI
    #[arg(long)]
    model: Option<String>,

    /// Overwrite output_path if it already exists
    #[arg(long)]
    overwrite: bool,
}

fn run(args: Args) -> Result<()> {
    let agent = Agent::from_str(&args.agent)?;
    let agents_file = agent.agents_file();

    let cve = fs::read_to_string(&args.cve_path)
        .with_context(|| format!("Failed to read CVE file: {}", args.cve_path.display()))?;

    prepare_output_path(&args.output_path, args.overwrite)?;
    fs::create_dir_all(&args.output_path)
        .with_context(|| format!("Failed to create output directory: {}", args.output_path.display()))?;

    let output_path = args.output_path.canonicalize()
        .with_context(|| format!("Failed to resolve output path: {}", args.output_path.display()))?;

    let prompt = SYNTHESIS_FROM_CVE_TEMPLATE
        .replace("{CVE}", &cve)
        .replace("{AGENTS_FILE}", agents_file)
        .replace("{OUTPUT_PATH}", &output_path.display().to_string());

    run_prompt(agent, &prompt, args.model.as_deref())?;
    
    let conclusion_path = output_path.join("conclusion.md");
    require_file(&conclusion_path, "final conclusion")?;

    Ok(())
}

fn main() {
    let args = Args::parse();
    
    if let Err(e) = run(args) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
