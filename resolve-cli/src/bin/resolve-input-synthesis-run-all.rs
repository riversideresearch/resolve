// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "resolve-input-synthesis-run-all",
    about = "Run the full CVE analysis pipeline: setup, CVE improvement, reachability analysis, and input synthesis. \
             The reasoning stages use debate and challenge/revise passes.",
    after_help = "Examples:\n  resolve-input-synthesis-run-all claude cve.json out/\n  resolve-input-synthesis-run-all codex cve.json out/"
)]
struct Args {
    /// Coding agent backend to execute prompts with
    #[arg(value_parser = ["claude", "codex", "opencode"])]
    agent: String,

    /// Path to the input CVE file
    cve_path: PathBuf,

    /// Top-level output directory. Subdirectories are created for each phase
    output_path: PathBuf,

    /// Optional model override passed through to the selected agent CLI
    #[arg(long)]
    model: Option<String>,

    /// Overwrite output subdirectories if they already exist
    #[arg(long)]
    overwrite: bool,
}

fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute {}", cmd))?;
    
    if !status.success() {
        anyhow::bail!("{} exited with status {}", cmd, status);
    }
    
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let improve_cve_path = args.output_path.join("improve_cve");
    let reachability_path = args.output_path.join("reachability");

    // Phase 1: Setup
    println!("\n=== Phase 1: Setup ===\n");
    let mut setup_args = vec![
        &args.agent as &str,
        args.cve_path.to_str().unwrap(),
    ];
    let model_str;
    if let Some(ref model) = args.model {
        setup_args.push("--model");
        model_str = model.clone();
        setup_args.push(&model_str);
    }
    run_command("resolve-input-synthesis-setup", &setup_args)?;

    // Phase 2: Improve CVE
    println!("\n=== Phase 2: Improve CVE ===\n");
    let mut improve_args = vec![
        &args.agent as &str,
        args.cve_path.to_str().unwrap(),
        improve_cve_path.to_str().unwrap(),
    ];
    if args.overwrite {
        improve_args.push("--overwrite");
    }
    if let Some(ref model) = args.model {
        improve_args.push("--model");
        improve_args.push(model);
    }
    run_command("resolve-input-synthesis-improve-cve", &improve_args)?;

    // Phase 3: Reachability Analysis
    println!("\n=== Phase 3: Reachability Analysis ===\n");
    let mut reachability_args = vec![
        &args.agent as &str,
        args.cve_path.to_str().unwrap(),
        improve_cve_path.to_str().unwrap(),
        reachability_path.to_str().unwrap(),
    ];
    if args.overwrite {
        reachability_args.push("--overwrite");
    }
    if let Some(ref model) = args.model {
        reachability_args.push("--model");
        reachability_args.push(model);
    }
    run_command("resolve-input-synthesis-reachability", &reachability_args)?;

    println!("\n=== Pipeline Complete ===\n");
    println!("Results written to:");
    println!("  - Improved CVE: {}", improve_cve_path.display());
    println!("  - Reachability: {}", reachability_path.display());

    Ok(())
}

fn main() {
    let args = Args::parse();
    
    if let Err(e) = run(args) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
