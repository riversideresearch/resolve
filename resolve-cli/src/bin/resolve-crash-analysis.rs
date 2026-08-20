// Copyright (c) 2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use resolve_cli::{Agent, prepare_output_path, require_file, run_prompt, validate_vulnerabilities_json};
use std::fs;
use std::path::PathBuf;

const COMMON_TEMPLATE: &str = include_str!("../../prompts/crash-analysis-common.txt");
const SYNTHESIS_TEMPLATE: &str = include_str!("../../prompts/crash-analysis-synthesis.txt");
const THESIS_TEMPLATE: &str = include_str!("../../prompts/crash-analysis-thesis.txt");
const ANTITHESIS_TEMPLATE: &str = include_str!("../../prompts/crash-analysis-antithesis.txt");
const FINAL_TEMPLATE: &str = include_str!("../../prompts/crash-analysis-final.txt");

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AgentArg {
    Claude,
    Codex,
    Opencode,
}

impl From<AgentArg> for Agent {
    fn from(arg: AgentArg) -> Self {
        match arg {
            AgentArg::Claude => Agent::Claude,
            AgentArg::Codex => Agent::Codex,
            AgentArg::Opencode => Agent::Opencode,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "resolve-crash-analysis",
    about = "Generate RESOLVE vulnerability artifacts from crash evidence.",
    after_help = "Examples:\n  \
        resolve-crash-analysis codex -i crash_dir\n  \
        resolve-crash-analysis codex -i crash_dir -s source_dir\n  \
        resolve-crash-analysis claude -i crash_dir -s source_dir -o out/crash-analysis"
)]
struct Args {
    /// Coding agent backend to execute prompts with
    #[arg(value_enum)]
    agent: AgentArg,

    /// Path to an input directory containing crash provenance and metadata
    #[arg(short = 'i', long = "input")]
    crash_dir: PathBuf,

    /// Path to the source code directory
    #[arg(short = 's', long = "source")]
    source_dir: Option<PathBuf>,

    /// Destination directory for final artifacts and intermediate reports
    #[arg(short = 'o', long = "output", default_value = "out")]
    output_path: PathBuf,

    /// Overwrite output_path if it already exists
    #[arg(long)]
    overwrite: bool,

    /// Optional model override passed through to the selected agent CLI
    #[arg(long)]
    model: Option<String>,
}

fn source_context(source_dir: Option<&PathBuf>) -> String {
    match source_dir {
        None => {
            "No source directory was provided. If source-level attribution is not \
             supported by the crash artifacts, say so explicitly."
                .to_string()
        }
        Some(dir) => {
            format!(
                "The source tree is available at `{}`. Use it to identify \
                 project-relative `affected-file` and source-level `affected-function` values.",
                dir.display()
            )
        }
    }
}

fn build_common_context(
    crash_dir: &PathBuf,
    source_dir: Option<&PathBuf>,
    output_path: &PathBuf,
    tmp_path: &PathBuf,
) -> String {
    COMMON_TEMPLATE
        .replace("{CRASH_DIR}", &crash_dir.display().to_string())
        .replace("{SOURCE_CONTEXT}", &source_context(source_dir))
        .replace("{OUTPUT_PATH}", &output_path.display().to_string())
        .replace("{TMP_PATH}", &tmp_path.display().to_string())
}

fn run(args: Args) -> Result<()> {
    let agent: Agent = args.agent.into();

    if !args.crash_dir.is_dir() {
        bail!("crash input directory does not exist: {}", args.crash_dir.display());
    }
    if let Some(ref source_dir) = args.source_dir {
        if !source_dir.is_dir() {
            bail!("source directory does not exist: {}", source_dir.display());
        }
    }

    prepare_output_path(&args.output_path, args.overwrite)?;

    let tmp_path = args.output_path.join("tmp");
    fs::create_dir_all(&tmp_path)
        .with_context(|| format!("Failed to create temporary directory: {}", tmp_path.display()))?;
    println!("Using temporary workspace: {}", tmp_path.display());

    let synthesis_path = args.output_path.join("synthesis.md");
    let thesis_path = args.output_path.join("thesis.md");
    let antithesis_path = args.output_path.join("antithesis.md");
    let vulnerabilities_path = args.output_path.join("vulnerabilities.json");
    let report_path = args.output_path.join("report.md");

    let common_context = build_common_context(
        &args.crash_dir,
        args.source_dir.as_ref(),
        &args.output_path,
        &tmp_path,
    );

    // Stage 1: Synthesis
    let synthesis_prompt = format!(
        "{}\n\n{}",
        common_context,
        SYNTHESIS_TEMPLATE.replace("{SYNTHESIS_PATH}", &synthesis_path.display().to_string())
    );

    run_prompt(agent, &synthesis_prompt, args.model.as_deref())?;
    require_file(&synthesis_path, "crash synthesis")?;

    // Stage 2: Thesis
    let thesis_prompt = format!(
        "{}\n\n{}",
        common_context,
        THESIS_TEMPLATE
            .replace("{SYNTHESIS_PATH}", &synthesis_path.display().to_string())
            .replace("{THESIS_PATH}", &thesis_path.display().to_string())
    );

    run_prompt(agent, &thesis_prompt, args.model.as_deref())?;
    require_file(&thesis_path, "crash thesis")?;

    // Stage 3: Antithesis
    let antithesis_prompt = format!(
        "{}\n\n{}",
        common_context,
        ANTITHESIS_TEMPLATE
            .replace("{SYNTHESIS_PATH}", &synthesis_path.display().to_string())
            .replace("{THESIS_PATH}", &thesis_path.display().to_string())
            .replace("{ANTITHESIS_PATH}", &antithesis_path.display().to_string())
    );

    run_prompt(agent, &antithesis_prompt, args.model.as_deref())?;
    require_file(&antithesis_path, "crash antithesis")?;

    // Stage 4: Final reconciliation
    let final_prompt = format!(
        "{}\n\n{}",
        common_context,
        FINAL_TEMPLATE
            .replace("{SYNTHESIS_PATH}", &synthesis_path.display().to_string())
            .replace("{THESIS_PATH}", &thesis_path.display().to_string())
            .replace("{ANTITHESIS_PATH}", &antithesis_path.display().to_string())
            .replace("{VULNERABILITIES_PATH}", &vulnerabilities_path.display().to_string())
            .replace("{REPORT_PATH}", &report_path.display().to_string())
    );

    run_prompt(agent, &final_prompt, args.model.as_deref())?;
    require_file(&vulnerabilities_path, "final vulnerabilities.json")?;
    require_file(&report_path, "final crash report")?;
    validate_vulnerabilities_json(&vulnerabilities_path)?;

    Ok(())
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("{:#}", e);
        std::process::exit(1);
    }
}
