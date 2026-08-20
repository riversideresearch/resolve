#!/usr/bin/env -S cargo +nightly -Zscript
//
// Copyright (c) 2025 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{Context, Result};
use clap::Parser;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Fact Extraction Helper.
#[derive(Parser, Debug)]
#[command(name = "resolve-get-facts", about = "Fact Extraction Helper.")]
struct Args {
    /// Path to the input bin to extract from
    #[arg(short = 'i', long = "in_bin", required = true)]
    in_bin: PathBuf,

    /// Path to the output directory
    #[arg(long = "out_dir")]
    out_dir: Option<PathBuf>,

    /// File to embed the output into
    #[arg(long = "out_bin")]
    out_bin: Option<PathBuf>,
}

/// Map of section names to file suffixes
const FACT_SECTION_MAP: &[(&str, &str)] = &[(".facts", ".facts")];

/// Check if compression should be used based on environment variable
fn use_compression() -> bool {
    env::var("RESOLVE_IGNORE_COMPRESSION").is_err()
}

/// Get the compression suffix based on environment variable
fn compression_suffix() -> &'static str {
    if use_compression() {
        ".zst"
    } else {
        ""
    }
}

/// Append facts to a section in the target binary
fn append_to_section(section: &str, input_file: &Path, target_bin: &Path) -> Result<()> {
    // Get current facts
    let output = Command::new("llvm-objcopy")
        .arg("--dump-section")
        .arg(format!("{}=/dev/stdout", section))
        .arg(target_bin)
        .output()
        .context("Failed to execute llvm-objcopy for dumping section")?;

    if !output.status.success() {
        anyhow::bail!(
            "llvm-objcopy dump failed with status: {}",
            output.status
        );
    }

    let mut facts = output.stdout;

    // Append new facts
    let mut new_facts = Vec::new();
    File::open(input_file)
        .with_context(|| format!("Failed to open input file: {}", input_file.display()))?
        .read_to_end(&mut new_facts)
        .context("Failed to read input file")?;

    facts.extend(new_facts);

    // Remove section
    let _status = Command::new("llvm-objcopy")
        .arg("--remove-section")
        .arg(section)
        .arg(target_bin)
        .status()
        .context("Failed to execute llvm-objcopy for removing section")?;

    // Note: Python script doesn't check=True for remove-section, so we don't fail here either

    // Replace section with merged facts
    let mut child = Command::new("llvm-objcopy")
        .arg("--add-section")
        .arg(format!("{}=/dev/stdin", section))
        .arg(target_bin)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn llvm-objcopy for adding section")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&facts)
            .context("Failed to write facts to llvm-objcopy stdin")?;
    }

    let status = child
        .wait()
        .context("Failed to wait for llvm-objcopy process")?;

    if !status.success() {
        anyhow::bail!(
            "llvm-objcopy add-section failed with status: {}",
            status
        );
    }

    Ok(())
}

/// Embed facts into the target binary
fn embed_facts(out_dir: &Path, target_bin: &Path) -> Result<()> {
    let out_file = |suffix: &str| -> PathBuf {
        let name = target_bin
            .file_stem()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        out_dir.join(format!("{}{}", name, suffix))
    };

    // Compress if needed
    if use_compression() {
        let mut cmd = Command::new("zstd");
        cmd.arg("-f");

        for (_, suffix) in FACT_SECTION_MAP {
            cmd.arg(out_file(suffix));
        }

        let status = cmd.status().context("Failed to execute zstd")?;

        if !status.success() {
            anyhow::bail!("zstd compression failed with status: {}", status);
        }
    }

    for (section, suffix) in FACT_SECTION_MAP {
        append_to_section(section, &out_file(suffix), target_bin)?;
    }

    Ok(())
}

/// Extract facts from the target binary
fn extract_facts(out_dir: &Path, target_bin: &Path) -> Result<()> {
    let out_file = |suffix: &str| -> PathBuf {
        let name = target_bin
            .file_stem()
            .unwrap_or_default()
            .to_str()
            .unwrap_or_default();
        out_dir.join(format!("{}{}{}", name, suffix, compression_suffix()))
    };

    for (section, suffix) in FACT_SECTION_MAP {
        // Check if section exists using objdump and grep
        let check_cmd = format!(
            "objdump -h \"{}\" | grep \"{}\"",
            target_bin.display(),
            section
        );

        let has_section = Command::new("sh")
            .arg("-c")
            .arg(&check_cmd)
            .status()
            .context("Failed to execute objdump")?
            .success();

        let contents = if !has_section {
            // No section
            Vec::new()
        } else {
            // Extract section contents
            let output = Command::new("llvm-objcopy")
                .arg("--dump-section")
                .arg(format!("{}=/dev/stdout", section))
                .arg(target_bin)
                .output()
                .context("Failed to execute llvm-objcopy for extracting section")?;

            if !output.status.success() {
                anyhow::bail!(
                    "llvm-objcopy extract failed with status: {}",
                    output.status
                );
            }

            output.stdout
        };

        // Write to output file (append mode)
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out_file(suffix))
            .with_context(|| format!("Failed to open output file: {}", out_file(suffix).display()))?;

        file.write_all(&contents)
            .context("Failed to write facts to output file")?;
    }

    // Decompress if needed
    if use_compression() {
        let mut cmd = Command::new("zstd");
        cmd.arg("-f").arg("-d");

        for (_, suffix) in FACT_SECTION_MAP {
            cmd.arg(out_file(suffix));
        }

        let status = cmd.status().context("Failed to execute zstd")?;

        if !status.success() {
            anyhow::bail!("zstd decompression failed with status: {}", status);
        }
    }

    Ok(())
}

/// Ingest facts from the input binary
fn ingest_facts(out_dir: &Path, in_bin: &Path) -> Result<()> {
    println!("Using input bin at {}", in_bin.display());
    extract_facts(out_dir, in_bin)
}

/// Export facts to the output binary
fn export_facts(out_dir: &Path, out_bin: Option<&Path>) -> Result<()> {
    if let Some(out_bin) = out_bin {
        println!("Embedding output into {}", out_bin.display());
        embed_facts(out_dir, out_bin)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = Args::parse();

    // Default out_dir to current directory if neither out_dir nor out_bin is specified
    if args.out_dir.is_none() && args.out_bin.is_none() {
        args.out_dir = Some(env::current_dir().context("Failed to get current directory")?);
    }

    if let Some(out_dir) = &args.out_dir {
        println!("Using out dir of {}", out_dir.display());
        ingest_facts(out_dir, &args.in_bin)?;
        export_facts(out_dir, args.out_bin.as_deref())?;
    } else {
        // Use temporary directory
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;
        let temp_path = temp_dir.path();
        ingest_facts(temp_path, &args.in_bin)?;
        export_facts(temp_path, args.out_bin.as_deref())?;
    }

    Ok(())
}
