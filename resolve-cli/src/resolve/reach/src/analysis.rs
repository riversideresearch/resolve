use facts_rs::FactsBuf;

use crate::{
    functions::FunctionIndex,
    libreach::Graph,
    vulnerability::{ReachabilityStatus, VulnerabilityAnalysis},
};

pub fn populate_reachability_results(
    analyses: &mut [VulnerabilityAnalysis],
    facts: &FactsBuf,
    functions: &FunctionIndex,
    entry: &str,
) -> Result<(), String> {
    let entry_id = functions
        .find(entry, "")
        .ok_or_else(|| format!("entry function '{entry}' was not found in the facts"))?;

    for analysis in analyses.iter_mut() {
        analysis.function_id = functions.find(
            &analysis.vuln.affected_function,
            &analysis.vuln.affected_file,
        );

        if analysis.function_id.is_none() && analysis.reachability == ReachabilityStatus::Unknown {
            analysis.reachability = ReachabilityStatus::NotFound;
        }
    }

    if !analyses
        .iter()
        .any(|analysis| analysis.reachability == ReachabilityStatus::Unknown)
    {
        return Ok(());
    }

    let graph = Graph::build(facts)?;
    println!(
        "[REACH] Built a libreach graph with {} edges.",
        graph.edge_count()
    );

    for analysis in analyses
        .iter_mut()
        .filter(|analysis| analysis.reachability == ReachabilityStatus::Unknown)
    {
        let destination = analysis
            .function_id
            .ok_or_else(|| "an unresolved analysis has no function ID".to_owned())?;
        analysis.paths = graph.query(entry_id, destination, 1)?;
        analysis.reachability = if analysis.paths.is_empty() {
            ReachabilityStatus::NoPath
        } else {
            ReachabilityStatus::Reachable
        };
    }

    Ok(())
}
