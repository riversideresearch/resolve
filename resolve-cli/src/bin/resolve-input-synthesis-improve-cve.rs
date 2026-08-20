// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{bail, Context, Result};
use clap::Parser;
use resolve_cli::{Agent, run_prompt, run_dialectic, run_critique, prepare_output_path, require_file};
use std::fs;
use std::path::{Path, PathBuf};

const DIALECTIC_AFFIRMATION: &str = include_str!("../../prompts/input-synthesis-improve-cve-dialectic-affirmation.txt");
const DIALECTIC_NEGATION: &str = include_str!("../../prompts/input-synthesis-improve-cve-dialectic-negation.txt");
const IMPROVE_PROMPT_TEMPLATE: &str = include_str!("../../prompts/input-synthesis-improve-cve-improve.txt");
const NECESSARY_CONDITIONS_TEMPLATE: &str = include_str!("../../prompts/input-synthesis-improve-cve-necessary-conditions.txt");
const SUFFICIENT_CONDITIONS_TEMPLATE: &str = include_str!("../../prompts/input-synthesis-improve-cve-sufficient-conditions.txt");
const CONDITION_NECESSARY_NEGATION: &str = include_str!("../../prompts/input-synthesis-improve-cve-condition-necessary-negation.txt");
const CONDITION_SUFFICIENT_NEGATION: &str = include_str!("../../prompts/input-synthesis-improve-cve-condition-sufficient-negation.txt");

#[derive(Parser)]
#[command(
    name = "resolve-input-synthesis-improve-cve",
    about = "Run a CVE-improvement pipeline with a coding agent. The pipeline uses a debate pass plus challenge/revise passes. \
             All intermediate artifacts are written under a unique /tmp workspace and final results are copied to output_path.",
    after_help = "Examples:\n  resolve-input-synthesis-improve-cve codex cve.json out/improve_cve\n  resolve-input-synthesis-improve-cve claude cve.json out/improve_cve"
)]
struct Args {
    /// Coding agent backend to execute prompts with
    #[arg(value_parser = ["claude", "codex", "opencode"])]
    agent: String,

    /// Path to the input CVE file used as the starting point
    cve_path: PathBuf,

    /// Destination directory for final artifacts copied from the temporary workspace
    output_path: PathBuf,

    /// Optional model override passed through to the selected agent CLI
    #[arg(long)]
    model: Option<String>,

    /// Overwrite output_path if it already exists
    #[arg(long)]
    overwrite: bool,
}

fn list_condition_files(path: &Path, role: &str) -> Result<Vec<PathBuf>> {
    let pattern = if role == "necessary" { "NC_" } else { "SC_" };
    
    if !path.is_dir() {
        return Ok(Vec::new());
    }
    
    let mut files: Vec<_> = fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|p| {
            p.is_file() &&
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(pattern) && n.ends_with(".md"))
                .unwrap_or(false)
        })
        .collect();
    
    files.sort();
    Ok(files)
}

fn refine_conditions(
    agent: Agent,
    cve_preamble: &str,
    source_dir: &Path,
    dest_dir: &Path,
    scratch_root: &Path,
    role: &str,
    model: Option<&str>,
) -> Result<()> {
    fs::create_dir_all(dest_dir)
        .with_context(|| format!("Failed to create directory: {}", dest_dir.display()))?;

    let negation = if role == "necessary" {
        CONDITION_NECESSARY_NEGATION
    } else if role == "sufficient" {
        CONDITION_SUFFICIENT_NEGATION
    } else {
        bail!("unknown role: {}", role);
    };

    let condition_files = list_condition_files(source_dir, role)?;
    if condition_files.is_empty() {
        println!("warning: no {} condition files found in {}", role, source_dir.display());
        return Ok(());
    }

    for p in condition_files {
        let condition = fs::read_to_string(&p)
            .with_context(|| format!("Failed to read condition file: {}", p.display()))?;
        
        let file_name = p.file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file name: {}", p.display()))?;
        let revised_condition_path = dest_dir.join(file_name);
        
        let stem = p.file_stem()
            .ok_or_else(|| anyhow::anyhow!("Invalid file stem: {}", p.display()))?;
        let p_tmp = scratch_root.join(role).join(stem);
        fs::create_dir_all(&p_tmp)
            .with_context(|| format!("Failed to create scratch directory: {}", p_tmp.display()))?;

        let preamble = format!("{}\n\n# Condition\n\n{}", cve_preamble, condition);

        run_critique(
            agent,
            &preamble,
            negation,
            &p_tmp,
            &revised_condition_path,
            model,
        )?;
        
        require_file(&revised_condition_path, &format!("{} condition refinement for {}", role, file_name.to_string_lossy()))?;
    }

    Ok(())
}

fn run(args: Args) -> Result<()> {
    let agent = Agent::from_str(&args.agent)?;

    let original_cve = fs::read_to_string(&args.cve_path)
        .with_context(|| format!("Failed to read CVE file: {}", args.cve_path.display()))?;
    
    let cve_name = args.cve_path
        .with_extension("")
        .to_string_lossy()
        .replace("/", "_");

    prepare_output_path(&args.output_path, args.overwrite)?;

    let tmp_path = args.output_path.join("tmp");
    fs::create_dir_all(&tmp_path)
        .with_context(|| format!("Failed to create tmp directory: {}", tmp_path.display()))?;
    println!("Using temporary workspace: {}", tmp_path.display());

    let cve_tmp_path = tmp_path.join(&cve_name);
    fs::create_dir_all(&cve_tmp_path)?;
    let scratch_root = tmp_path.join("critique_scratch");

    // Canonicalize paths for use in prompts
    let cve_path_abs = args.cve_path.canonicalize()
        .with_context(|| format!("Failed to resolve CVE path: {}", args.cve_path.display()))?;
    let cve_tmp_path_abs = cve_tmp_path.canonicalize()
        .with_context(|| format!("Failed to resolve temp path: {}", cve_tmp_path.display()))?;

    ////////////////////////////////////////////////////////////////////////////
    // FIRST PASS IMPROVEMENT
    ////////////////////////////////////////////////////////////////////////////

    let cve_preamble = format!("# CVE\n\n{}", original_cve);

    run_dialectic(
        agent,
        &cve_preamble,
        DIALECTIC_AFFIRMATION,
        DIALECTIC_NEGATION,
        &cve_tmp_path_abs,
        args.model.as_deref(),
    )?;
    
    require_file(&cve_tmp_path.join("thesis.md"), "CVE dialectic thesis")?;
    require_file(&cve_tmp_path.join("antithesis.md"), "CVE dialectic antithesis")?;
    require_file(&cve_tmp_path.join("synthesis.md"), "CVE dialectic synthesis")?;

    let improved_cve_path = cve_tmp_path.join(args.cve_path.file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid CVE file name"))?);
    let improved_cve_path_abs = cve_tmp_path_abs.join(args.cve_path.file_name().unwrap());

    let cve_improve_prompt = IMPROVE_PROMPT_TEMPLATE
        .replace("{CVE_PREAMBLE}", &cve_preamble)
        .replace("{SYNTHESIS_PATH}", &cve_tmp_path_abs.display().to_string())
        .replace("{IMPROVED_CVE_PATH}", &improved_cve_path_abs.display().to_string());

    run_prompt(agent, &cve_improve_prompt, args.model.as_deref())?;
    require_file(&improved_cve_path, "CVE improvement")?;

    ////////////////////////////////////////////////////////////////////////////
    // NECESSARY CONDITION INFERENCE
    ////////////////////////////////////////////////////////////////////////////

    let necessary_conditions_path = cve_tmp_path.join("necessary_conditions");
    fs::create_dir_all(&necessary_conditions_path)?;
    let necessary_conditions_path_abs = necessary_conditions_path.canonicalize()
        .with_context(|| format!("Failed to resolve necessary conditions path"))?;

    let condition_preamble = format!(
        "# CVE\n\n`{}` describes a CVE affecting this project. `{}` is a derived description that may provide more detail.",
        cve_path_abs.display(),
        improved_cve_path_abs.display()
    );

    let necessary_conditions_prompt = NECESSARY_CONDITIONS_TEMPLATE
        .replace("{CONDITION_PREAMBLE}", &condition_preamble)
        .replace("{NECESSARY_CONDITIONS_PATH}", &necessary_conditions_path_abs.display().to_string());

    run_prompt(agent, &necessary_conditions_prompt, args.model.as_deref())?;

    ////////////////////////////////////////////////////////////////////////////
    // NECESSARY CONDITION WEAKENING
    ////////////////////////////////////////////////////////////////////////////

    let revised_necessary_conditions_path = cve_tmp_path.join("necessary_conditions_revised");

    refine_conditions(
        agent,
        &condition_preamble,
        &necessary_conditions_path,
        &revised_necessary_conditions_path,
        &scratch_root,
        "necessary",
        args.model.as_deref(),
    )?;

    let revised_necessary_conditions_path_abs = revised_necessary_conditions_path.canonicalize()
        .with_context(|| format!("Failed to resolve revised necessary conditions path"))?;

    ////////////////////////////////////////////////////////////////////////////
    // SUFFICIENT CONDITION INFERENCE
    ////////////////////////////////////////////////////////////////////////////

    let sufficient_conditions_path = cve_tmp_path.join("sufficient_conditions");
    fs::create_dir_all(&sufficient_conditions_path)?;
    let sufficient_conditions_path_abs = sufficient_conditions_path.canonicalize()
        .with_context(|| format!("Failed to resolve sufficient conditions path"))?;

    let sufficient_conditions_prompt = SUFFICIENT_CONDITIONS_TEMPLATE
        .replace("{CVE_PATH}", &cve_path_abs.display().to_string())
        .replace("{IMPROVED_CVE_PATH}", &improved_cve_path_abs.display().to_string())
        .replace("{REVISED_NECESSARY_CONDITIONS_PATH}", &revised_necessary_conditions_path_abs.display().to_string())
        .replace("{SUFFICIENT_CONDITIONS_PATH}", &sufficient_conditions_path_abs.display().to_string());

    run_prompt(agent, &sufficient_conditions_prompt, args.model.as_deref())?;

    ////////////////////////////////////////////////////////////////////////////
    // SUFFICIENT CONDITION STRENGTHENING
    ////////////////////////////////////////////////////////////////////////////

    let revised_sufficient_conditions_path = cve_tmp_path.join("sufficient_conditions_revised");

    refine_conditions(
        agent,
        &condition_preamble,
        &sufficient_conditions_path,
        &revised_sufficient_conditions_path,
        &scratch_root,
        "sufficient",
        args.model.as_deref(),
    )?;

    ////////////////////////////////////////////////////////////////////////////
    // COPY FINAL RESULTS TO OUTPUT PATH
    ////////////////////////////////////////////////////////////////////////////

    fs::create_dir_all(&args.output_path)?;

    fs::copy(&improved_cve_path, args.output_path.join(improved_cve_path.file_name().unwrap()))
        .with_context(|| format!("Failed to copy improved CVE file"))?;
    
    copy_dir_all(&revised_necessary_conditions_path, &args.output_path.join("necessary_conditions"))?;
    copy_dir_all(&revised_sufficient_conditions_path, &args.output_path.join("sufficient_conditions"))?;

    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("Failed to create directory: {}", dst.display()))?;
    
    for entry in fs::read_dir(src)
        .with_context(|| format!("Failed to read directory: {}", src.display()))? 
    {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        
        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)
                .with_context(|| format!("Failed to copy {} to {}", src_path.display(), dst_path.display()))?;
        }
    }
    
    Ok(())
}

fn main() {
    let args = Args::parse();
    
    if let Err(e) = run(args) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
