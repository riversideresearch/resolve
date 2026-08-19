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
#[command(
    name = "resolve-reach",
    about = "Analyze static reachability for known vulnerabilities"
)]
struct Args {
    /// Input vulnerabilities.json
    #[arg(short, long)]
    input: PathBuf,

    /// Files or directories containing facts (ELF, .so, .facts)
    #[arg(short, long, required = true, num_args=1, action= ArgAction::Append)]
    facts: Vec<PathBuf>,

    /// The file to write the final report into
    #[arg(short, long)]
    output: Option<PathBuf>,

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

fn expand_facts_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();

    for path in paths {
        if !path.is_dir() {
            files.push(path.clone());
            continue;
        }

        let mut directory_files = fs::read_dir(path)
            .map_err(|error| format!("failed to read '{}': {error}", path.display()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| format!("failed to read '{}': {error}", path.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        directory_files.retain(|file| {
            file.is_file()
                && file
                    .extension()
                    .is_some_and(|extension| extension == "facts")
        });
        directory_files.sort();

        if directory_files.is_empty() {
            return Err(format!(
                "facts directory '{}' contains no .facts files",
                path.display()
            ));
        }
        files.extend(directory_files);
    }

    Ok(files)
}

fn load_facts(paths: &[PathBuf]) -> Result<(FactsBuf, usize), String> {
    let files = expand_facts_paths(paths)?;
    let count = files.len();
    let facts =
        FactsBuf::read_files(&files).map_err(|error| format!("failed to load facts: {error}"))?;

    Ok((facts, count))
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
    let output = args
        .output
        .unwrap_or_else(|| args.input.with_extension("reach.json"));
    let mut analyses: Vec<VulnerabilityAnalysis> =
        input.vulnerabilities.into_iter().map(Into::into).collect();

    if let Some(src_dir) = args.src.as_deref() {
        populate_version_results(&mut analyses, src_dir)?;
    } else {
        println!(
            "[REACH] WARNING: No source code directory provided, package versions will not be populated."
        );
    }

    let (facts, facts_file_count) = load_facts(&args.facts)?;
    let module_count = facts
        .view()
        .modules()
        .try_fold(0usize, |count, module| module.map(|_| count + 1))
        .map_err(|error| format!("failed to iterate over facts modules: {error}"))?;

    println!(
        "[REACH] Loaded {module_count} facts modules from {} input files.",
        facts_file_count
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
    write_report(&output, &analyses, &facts, &functions)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
