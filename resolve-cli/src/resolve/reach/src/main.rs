use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::{ArgAction, Parser};
use facts_rs::FactsBuf;
use serde::Deserialize;

use analysis::populate_reachability_results;
use functions::FunctionIndex;
use libreach::{GraphBuildOptions, LoadedSymbol};
use serializer::write_report;
use vcpkg::populate_version_results;
use vulnerability::{VulnerabilityAnalysis, VulnerabilityJSON};

mod analysis;
mod functions;
mod libreach;
mod serializer;
mod vcpkg;
mod vulnerability;

#[derive(Parser, Debug)]
struct Args {
    /// Input vulnerabilities.json
    #[arg(short, long)]
    input: PathBuf,

    /// Files containing facts (ELF, .so, .facts)
    #[arg(short, long, required = true, num_args=1, action= ArgAction::Append)]
    facts: Vec<PathBuf>,

    /// The file to write the final report into
    #[arg(short, long, default_value = "reach.json")] // TODO: <input>.reach.json
    output: PathBuf,

    /// Source tree containing vcpkg-overlays
    #[arg(short, long)]
    src: Option<PathBuf>,

    // TODO: C++ WORKER ARGS HERE FOR OTHER SETTINGS
    /// Entry function to traverse to vulnerable sink from
    #[arg(short, long, default_value = "main")]
    entry: String,

    /// Include external-linkage functions as indirect-call targets
    #[arg(long)]
    dynlink: bool,

    /// JSON log of symbols loaded through dlsym
    #[arg(long)]
    dlsym_log: Option<PathBuf>,
}

#[derive(Deserialize)]
struct DlsymLog {
    loaded_symbols: Vec<LoadedSymbol>,
}

fn load_vuln_json(path: &Path) -> Result<VulnerabilityJSON, String> {
    let contents =
        fs::read(path).map_err(|error| format!("failed to read '{}': {error}", path.display()))?;

    serde_json::from_slice(&contents)
        .map_err(|error| format!("failed to parse '{}': {error}", path.display()))
}

fn load_facts(paths: &[PathBuf]) -> Result<FactsBuf, String> {
    FactsBuf::read_files(paths).map_err(|error| format!("failed to load facts: {error}"))
}

fn load_dlsym_log(path: &Path) -> Result<Vec<LoadedSymbol>, String> {
    let contents =
        fs::read(path).map_err(|error| format!("failed to read '{}': {error}", path.display()))?;
    let log: DlsymLog = serde_json::from_slice(&contents)
        .map_err(|error| format!("failed to parse '{}': {error}", path.display()))?;

    Ok(log.loaded_symbols)
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let input = load_vuln_json(&args.input)?;
    let mut analyses: Vec<VulnerabilityAnalysis> =
        input.vulnerabilities.into_iter().map(Into::into).collect();

    if let Some(src_dir) = args.src.as_deref() {
        populate_version_results(&mut analyses, src_dir)?;
    } else {
        println!(
            "[REACH] WARNING: No source code directory provided, package versions will not be populated."
        );
    }

    let facts = load_facts(&args.facts)?;
    let module_count = facts
        .view()
        .modules()
        .try_fold(0usize, |count, module| module.map(|_| count + 1))
        .map_err(|error| format!("failed to iterate over facts modules: {error}"))?;

    println!(
        "[REACH] Loaded {module_count} facts modules from {} input files.",
        args.facts.len()
    );

    let functions = FunctionIndex::build(&facts)?;
    let loaded_symbols = args.dlsym_log.as_deref().map(load_dlsym_log).transpose()?;
    let graph_options = GraphBuildOptions {
        loaded_symbols: loaded_symbols.as_deref(),
        dynlink: args.dynlink,
    };
    populate_reachability_results(
        &mut analyses,
        &facts,
        &functions,
        &args.entry,
        &graph_options,
    )?;
    write_report(&args.output, &analyses, &facts, &functions)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
