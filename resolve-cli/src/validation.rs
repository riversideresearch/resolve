// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const REQUIRED_VULNERABILITY_KEYS: &[&str] = &[
    "cve-id",
    "cve-description",
    "package-name",
    "package-version",
    "cwe-id",
    "cwe-name",
    "affected-function",
    "affected-file",
    "remediation-strategy",
];

const OPTIONAL_VULNERABILITY_KEYS: &[&str] = &["undesirable-function"];

const REMEDIATION_STRATEGIES: &[&str] = &[
    "exit", "recover", "sat", "widen", "continue", "none", "wrap",
];

fn validate_string_field(vuln: &Value, key: &str, index: usize) -> Result<()> {
    let value = vuln
        .get(key)
        .with_context(|| format!("vulnerabilities[{}].{} is missing", index, key))?;
    
    let string_value = value
        .as_str()
        .with_context(|| format!("vulnerabilities[{}].{} must be a string", index, key))?;
    
    if string_value.is_empty() {
        bail!("vulnerabilities[{}].{} must not be empty", index, key);
    }
    
    Ok(())
}

pub fn validate_vulnerabilities_json(path: &Path) -> Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    
    let document: Value = serde_json::from_str(&content)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    
    if !document.is_object() {
        bail!("{} must contain a top-level JSON object", path.display());
    }
    
    let obj = document.as_object().unwrap();
    let top_level_keys: HashSet<_> = obj.keys().map(|s| s.as_str()).collect();
    let expected_keys: HashSet<_> = ["vulnerabilities"].iter().copied().collect();
    
    if top_level_keys != expected_keys {
        let extra: Vec<_> = top_level_keys.difference(&expected_keys).collect();
        let missing: Vec<_> = expected_keys.difference(&top_level_keys).collect();
        
        let mut details = Vec::new();
        if !missing.is_empty() {
            details.push(format!("missing {:?}", missing));
        }
        if !extra.is_empty() {
            details.push(format!("unexpected {:?}", extra));
        }
        
        bail!(
            "{} must contain exactly the top-level key 'vulnerabilities': {}",
            path.display(),
            details.join(", ")
        );
    }
    
    let vulnerabilities = document
        .get("vulnerabilities")
        .unwrap()
        .as_array()
        .with_context(|| format!("{} field 'vulnerabilities' must be an array", path.display()))?;
    
    let allowed_keys: HashSet<_> = REQUIRED_VULNERABILITY_KEYS
        .iter()
        .chain(OPTIONAL_VULNERABILITY_KEYS.iter())
        .copied()
        .collect();
    
    let required_keys: HashSet<_> = REQUIRED_VULNERABILITY_KEYS.iter().copied().collect();
    
    for (index, vuln) in vulnerabilities.iter().enumerate() {
        if !vuln.is_object() {
            bail!("vulnerabilities[{}] must be an object", index);
        }
        
        let vuln_obj = vuln.as_object().unwrap();
        let keys: HashSet<_> = vuln_obj.keys().map(|s| s.as_str()).collect();
        
        let missing: Vec<_> = required_keys.difference(&keys).collect();
        let extra: Vec<_> = keys.difference(&allowed_keys).collect();
        
        if !missing.is_empty() {
            bail!(
                "vulnerabilities[{}] is missing required keys: {:?}",
                index,
                missing
            );
        }
        if !extra.is_empty() {
            bail!(
                "vulnerabilities[{}] has unexpected keys: {:?}",
                index,
                extra
            );
        }
        
        for &key in REQUIRED_VULNERABILITY_KEYS {
            validate_string_field(vuln, key, index)?;
        }
        
        if vuln.get("undesirable-function").is_some() {
            validate_string_field(vuln, "undesirable-function", index)?;
        }
        
        let cwe_id = vuln.get("cwe-id").unwrap().as_str().unwrap();
        if !cwe_id.chars().all(|c| c.is_ascii_digit()) {
            bail!(
                "vulnerabilities[{}].cwe-id must be a numeric string without a CWE- prefix",
                index
            );
        }
        
        let remediation = vuln.get("remediation-strategy").unwrap().as_str().unwrap();
        if !REMEDIATION_STRATEGIES.contains(&remediation) {
            bail!(
                "vulnerabilities[{}].remediation-strategy must be one of {:?}",
                index,
                REMEDIATION_STRATEGIES
            );
        }
    }
    
    Ok(())
}
