use std::{
    io::Write,
    process::{Command, Stdio},
};

use facts_rs::{FactsBuf, NodeType};

use crate::libreach::ReachNodeID;

#[derive(Debug)]
struct Function {
    id: ReachNodeID,
    symbol: String,
    demangled: String,
    source_file: String,
    module_file: String,
}

#[derive(Debug)]
pub struct FunctionIndex {
    functions: Vec<Function>,
}

impl FunctionIndex {
    pub fn build(facts: &FactsBuf) -> Result<Self, String> {
        let mut functions = Vec::new();

        for (module_index, module) in facts.view().modules().enumerate() {
            let module = module
                .map_err(|error| format!("failed to read facts module {module_index}: {error}"))?;
            let module_id = u32::try_from(module_index)
                .map_err(|_| "facts contain too many modules".to_owned())?;
            let module_file = module
                .node_ref(0)
                .and_then(|node| node.source_file())
                .unwrap_or_default()
                .to_owned();

            for node in module.node_refs() {
                if node.node_type() != Ok(NodeType::Function) {
                    continue;
                }
                let Some(symbol) = node.name() else {
                    continue;
                };

                functions.push(Function {
                    id: ReachNodeID {
                        module: module_id,
                        node: node.id(),
                    },
                    symbol: symbol.to_owned(),
                    demangled: String::new(),
                    source_file: node.source_file().unwrap_or_default().to_owned(),
                    module_file: module_file.clone(),
                });
            }
        }

        let symbols = functions
            .iter()
            .map(|function| function.symbol.as_str())
            .collect::<Vec<_>>();
        let demangled = demangle(&symbols)?;
        for (function, demangled) in functions.iter_mut().zip(demangled) {
            function.demangled = demangled;
        }

        Ok(Self { functions })
    }

    pub fn find(&self, name: &str, file: &str) -> Option<ReachNodeID> {
        if let Some(function) = self
            .functions
            .iter()
            .find(|function| function.symbol == name && function.matches_file(file))
        {
            return Some(function.id);
        }

        let matches = self
            .functions
            .iter()
            .filter(|function| function.demangled.contains(name) && function.matches_file(file))
            .collect::<Vec<_>>();

        if matches.len() > 1 {
            println!(
                "[REACH] WARNING: Multiple functions match '{}:{}'. Using '{}'.",
                file, name, matches[0].demangled
            );
        }

        matches.first().map(|function| function.id)
    }

    pub fn display_name(&self, id: ReachNodeID) -> Option<&str> {
        self.functions
            .iter()
            .find(|function| function.id == id)
            .map(|function| function.demangled.as_str())
    }
}

impl Function {
    fn matches_file(&self, file: &str) -> bool {
        file.is_empty() || self.source_file.contains(file) || self.module_file.contains(file)
    }
}

fn demangle(symbols: &[&str]) -> Result<Vec<String>, String> {
    if symbols.is_empty() {
        return Ok(Vec::new());
    }

    let input = format!("{}\n", symbols.join("\n"));
    let mut child = Command::new("c++filt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start c++filt: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open c++filt input".to_owned())?;
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for c++filt: {error}"))?;

    let write_result = writer
        .join()
        .map_err(|_| "c++filt input writer panicked".to_owned())?;
    if !output.status.success() {
        return Err(format!(
            "c++filt failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    write_result.map_err(|error| format!("failed to write to c++filt: {error}"))?;

    let demangled = String::from_utf8(output.stdout)
        .map_err(|error| format!("c++filt returned invalid UTF-8: {error}"))?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if demangled.len() != symbols.len() {
        return Err(format!(
            "c++filt returned {} names for {} symbols",
            demangled.len(),
            symbols.len()
        ));
    }

    Ok(demangled)
}
