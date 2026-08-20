// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser)]
#[command(name = "resolve", version, disable_help_subcommand = true)]
struct Cli {
    #[arg(help = "Subcommand to execute")]
    subcommand: Option<String>,
    
    #[arg(short = 'V', long)]
    version: bool,
    
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn find_subcommands(program: &str) -> HashMap<String, PathBuf> {
    let prefix = format!("{}-", program);
    let path_var = env::var_os("PATH").unwrap_or_default();
    let mut subcommands = HashMap::new();
    
    let argv0_path = env::args().next().map(PathBuf::from);
    let mut search_paths: Vec<PathBuf> = Vec::new();
    
    if let Some(argv0) = argv0_path {
        if let Some(parent) = argv0.parent() {
            if parent != Path::new(".") {
                if let Ok(resolved) = parent.canonicalize() {
                    search_paths.push(resolved);
                }
            }
        }
    }
    
    search_paths.extend(env::split_paths(&path_var));
    
    for path in search_paths {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                let file_name = entry.file_name();
                if let Some(name) = file_name.to_str() {
                    if name.starts_with(&prefix) {
                        if let Ok(metadata) = entry.metadata() {
                            if metadata.is_file() && is_executable(&metadata) {
                                let subcommand = &name[prefix.len()..];
                                subcommands
                                    .entry(subcommand.to_string())
                                    .or_insert_with(|| entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
    
    subcommands
}

fn show_help(subcommands: &HashMap<String, PathBuf>) {
    println!("usage: resolve <subcommand> [args...]");
    println!();
    println!("built-in commands:");
    println!("  help [subcommand]");
    println!("  version");
    println!();
    println!("available subcommands:");
    let mut names: Vec<_> = subcommands.keys().collect();
    names.sort();
    for name in names {
        println!("  {}", name);
    }
}

fn show_unknown_subcommand(sub: &str, subcommands: &HashMap<String, PathBuf>) {
    eprintln!("usage: resolve <subcommand> [args...]");
    eprintln!("error: unknown subcommand: {}", sub);
    eprintln!();
    eprintln!("available subcommands:");
    let mut names: Vec<_> = subcommands.keys().collect();
    names.sort();
    for name in names {
        eprintln!("  {}", name);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let program_name = env::args()
        .next()
        .and_then(|p| {
            Path::new(&p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "resolve".to_string());
    
    if cli.version || cli.subcommand.as_deref() == Some("version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    
    let subcommands = find_subcommands(&program_name);
    
    let Some(subcommand) = cli.subcommand else {
        show_help(&subcommands);
        return Ok(());
    };
    
    if subcommand == "help" {
        if cli.args.is_empty() {
            show_help(&subcommands);
        } else if let Some(cmd_path) = subcommands.get(&cli.args[0]) {
            Command::new(cmd_path).arg("--help").status()?;
        } else {
            show_unknown_subcommand(&cli.args[0], &subcommands);
            std::process::exit(1);
        }
        return Ok(());
    }
    
    let Some(cmd_path) = subcommands.get(&subcommand) else {
        show_unknown_subcommand(&subcommand, &subcommands);
        std::process::exit(1);
    };
    
    let status = Command::new(cmd_path).args(&cli.args).status()?;
    
    std::process::exit(status.code().unwrap_or(1));
}
