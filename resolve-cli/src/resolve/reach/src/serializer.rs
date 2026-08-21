use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

use facts_rs::FactsBuf;
use serde::Serialize;

use crate::{
    functions::FunctionIndex,
    libreach::{ReachEdgeType, ReachNodeID, ReachPath},
    vulnerability::{ReachabilityStatus, VulnerabilityAnalysis},
};

#[derive(Serialize)]
struct ReachabilityReport {
    reachability_results: Vec<ReportResult>,
}

#[derive(Serialize)]
struct ReportResult {
    cve_id: String,
    classification: &'static str,
    justification: Justification,
}

#[derive(Serialize)]
struct Justification {
    conclusion: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call_path: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_flow_path: Option<Vec<String>>,
}

pub fn write_report(
    path: &Path,
    analyses: &[VulnerabilityAnalysis],
    facts: &FactsBuf,
    functions: &FunctionIndex,
) -> Result<(), String> {
    let report = build_report(analyses, facts, functions)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create '{}': {error}", parent.display()))?;
    }

    let file = File::create(path)
        .map_err(|error| format!("failed to create '{}': {error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &report)
        .map_err(|error| format!("failed to serialize '{}': {error}", path.display()))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("failed to write '{}': {error}", path.display()))?;
    writer
        .flush()
        .map_err(|error| format!("failed to write '{}': {error}", path.display()))?;

    println!("[REACH] Wrote '{}'.", path.display());
    Ok(())
}

fn build_report(
    analyses: &[VulnerabilityAnalysis],
    facts: &FactsBuf,
    functions: &FunctionIndex,
) -> Result<ReachabilityReport, String> {
    let reachability_results = analyses
        .iter()
        .map(|analysis| build_result(analysis, facts, functions))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReachabilityReport {
        reachability_results,
    })
}

fn build_result(
    analysis: &VulnerabilityAnalysis,
    facts: &FactsBuf,
    functions: &FunctionIndex,
) -> Result<ReportResult, String> {
    let target = format!(
        "{}:{}",
        analysis.vuln.affected_file, analysis.vuln.affected_function
    );

    let (classification, justification) = match analysis.reachability {
        ReachabilityStatus::NotFound => (
            "unreachable",
            Justification::new(
                "Not Found",
                format!(
                    "The affected function {target} was not found in compiled program metadata."
                ),
            ),
        ),
        ReachabilityStatus::NoPath => (
            "unreachable",
            Justification::new(
                "Not Reachable",
                format!(
                    "Control Flow Graph analysis found no paths to target function {target}."
                ),
            ),
        ),
        ReachabilityStatus::NotVulnerable => (
            "unreachable",
            Justification::new(
                "Not Vulnerable",
                "The package version is not considered vulnerable according to the supplied version information. It may or may not still be reachable."
                    .to_owned(),
            ),
        ),
        ReachabilityStatus::Reachable => {
            let path = analysis
                .paths
                .first()
                .ok_or_else(|| format!("reachable result '{}' has no path", analysis.vuln.cve_id))?;
            let (call_path, control_flow_path) = format_path(path, facts, functions)?;
            (
                "potentially reachable",
                Justification {
                    conclusion: "Statically Reachable",
                    reason: Some(
                        "Control Flow Graph analysis found the following candidate path..."
                            .to_owned(),
                    ),
                    call_path: Some(call_path),
                    control_flow_path: Some(control_flow_path),
                },
            )
        }
        ReachabilityStatus::Unknown => (
            "Unable to assess",
            Justification {
                conclusion: "Error: internal tool failure",
                reason: None,
                call_path: None,
                control_flow_path: None,
            },
        ),
    };

    Ok(ReportResult {
        cve_id: analysis.vuln.cve_id.clone(),
        classification,
        justification,
    })
}

fn format_path(
    path: &ReachPath,
    facts: &FactsBuf,
    functions: &FunctionIndex,
) -> Result<(Vec<String>, Vec<String>), String> {
    if path.nodes.len() != path.edges.len() + 1 {
        return Err("libreach returned a path with mismatched nodes and edges".to_owned());
    }

    let nodes = path
        .nodes
        .iter()
        .copied()
        .map(|id| format_node(id, facts, functions))
        .collect::<Result<Vec<_>, _>>()?;
    let mut call_path = vec![nodes[0].clone()];
    let mut control_flow_path = vec![nodes[0].clone()];

    for (edge, formatted_node) in path.edges.iter().zip(nodes.into_iter().skip(1)) {
        let step = format!("{} -> {formatted_node}", edge.as_str());
        control_flow_path.push(step.clone());
        if !matches!(edge, ReachEdgeType::Contains | ReachEdgeType::Successor) {
            call_path.push(step);
        }
    }

    Ok((call_path, control_flow_path))
}

fn format_node(
    id: ReachNodeID,
    facts: &FactsBuf,
    functions: &FunctionIndex,
) -> Result<String, String> {
    let module = facts
        .view()
        .modules()
        .nth(id.module as usize)
        .ok_or_else(|| format!("facts do not contain module {}", id.module))?
        .map_err(|error| format!("failed to read facts module {}: {error}", id.module))?;
    let node = module.node_ref(id.node).ok_or_else(|| {
        format!(
            "facts module {} does not contain node {}",
            id.module, id.node
        )
    })?;
    let kind = node
        .node_type()
        .map_err(|value| format!("facts node ({}, {}) has type {value}", id.module, id.node))?;
    let name = functions
        .display_name(id)
        .map(str::to_owned)
        .or_else(|| node.name().map(str::to_owned))
        .or_else(|| node.idx().map(|index| index.to_string()))
        .unwrap_or_default();

    Ok(format!("{kind:?}({name}) (({}, {}))", id.module, id.node))
}

impl Justification {
    fn new(conclusion: &'static str, reason: String) -> Self {
        Self {
            conclusion,
            reason: Some(reason),
            call_path: None,
            control_flow_path: None,
        }
    }
}
