// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::Result;
use std::env;
use std::process::Command;

const HELP_TEXT: &str = r#"resolve-input-synthesis - CVE analysis and input synthesis toolchain

USAGE:
    resolve-input-synthesis <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    setup           Prepare a target project for CVE analysis
    improve-cve     Run CVE improvement pipeline with debate and challenge/revise passes
    reachability    Run reachability analysis on improved CVE conditions
    synthesize      Synthesize and verify triggering input directly from CVE
    run-all         Run the full pipeline (setup + improve + reachability + synthesis)

Run 'resolve-input-synthesis <SUBCOMMAND> --help' for more information on a specific subcommand.

EXAMPLES:
    resolve-input-synthesis setup claude cve.json
    resolve-input-synthesis improve-cve codex cve.json out/improve_cve
    resolve-input-synthesis reachability claude cve.json out/improve_cve out/reachability
    resolve-input-synthesis synthesize codex cve.json out/synthesize
    resolve-input-synthesis run-all claude cve.json out/
"#;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print!("{}", HELP_TEXT);
        return Ok(());
    }
    
    let subcommand = &args[1];
    
    if subcommand == "-h" || subcommand == "--help" {
        print!("{}", HELP_TEXT);
        return Ok(());
    }
    
    let binary_name = match subcommand.as_str() {
        "setup" => "resolve-input-synthesis-setup",
        "improve-cve" => "resolve-input-synthesis-improve-cve",
        "reachability" => "resolve-input-synthesis-reachability",
        "synthesize" => "resolve-input-synthesis-synthesize",
        "run-all" => "resolve-input-synthesis-run-all",
        _ => {
            eprintln!("Unknown subcommand: {}\n", subcommand);
            print!("{}", HELP_TEXT);
            std::process::exit(1);
        }
    };
    
    // Pass remaining args to the subcommand
    let subcommand_args = &args[2..];
    
    let status = Command::new(binary_name)
        .args(subcommand_args)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to execute {}: {}", binary_name, e))?;
    
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    
    Ok(())
}
