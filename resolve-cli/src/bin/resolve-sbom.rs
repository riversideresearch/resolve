use anyhow::{anyhow, Context, Result};
use clap::Parser;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;
use tokio;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CWE_API_BASE: &str = "https://cwe-api.mitre.org/api/v1/cwe/weakness";

#[derive(Parser, Debug)]
#[command(name = "resolve-sbom")]
#[command(about = "Identify known CVEs / CWEs for a given SBOM")]
struct Args {
    /// Path to the input SBOM file(s)
    #[arg(value_name = "SBOM")]
    sbom: Vec<PathBuf>,

    /// Path of output file
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,

    /// Vulnerability id of interest
    #[arg(long = "id", value_name = "ID")]
    id: Vec<String>,

    /// Minimum CVSS v3 base score
    #[arg(long = "min-score")]
    min_score: Option<f64>,

    /// Filter deferred vulnerabilities
    #[arg(long = "filter-deferred")]
    filter_deferred: bool,

    /// Filter disputed vulnerabilities
    #[arg(long = "filter-disputed")]
    filter_disputed: bool,

    /// Filter rejected vulnerabilities
    #[arg(long = "filter-rejected")]
    filter_rejected: bool,

    /// LLM provider (gemini, ollama, opencode)
    #[arg(short = 'L', long = "llm-provider", value_name = "PROVIDER")]
    llm_provider: Option<String>,
}

// ============================================================================
// SPDX Dependency Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoftwareDependency {
    name: String,
    version: String,
    #[serde(skip)]
    cves: Vec<CveItem>,
}

impl PartialEq for SoftwareDependency {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.version == other.version
    }
}

impl Eq for SoftwareDependency {}

impl std::hash::Hash for SoftwareDependency {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.version.hash(state);
    }
}

impl SoftwareDependency {
    fn as_query(&self) -> String {
        let name_part = self.name.split(':').next().unwrap_or(&self.name);
        format!("cpe:2.3:*:*:{}:{}:*:*:*", name_part, self.version)
    }
}

// ============================================================================
// NIST API Models (minimal structs for what we need)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NvdApiResponse {
    #[serde(rename = "resultsPerPage")]
    results_per_page: usize,
    #[serde(rename = "startIndex")]
    start_index: usize,
    #[serde(rename = "totalResults")]
    total_results: usize,
    vulnerabilities: Vec<VulnerabilityWrapper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VulnerabilityWrapper {
    cve: CveItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CveItem {
    id: String,
    #[serde(rename = "sourceIdentifier")]
    source_identifier: Option<String>,
    #[serde(rename = "vulnStatus")]
    vuln_status: Option<String>,
    descriptions: Vec<LangString>,
    metrics: Option<Metrics>,
    weaknesses: Option<Vec<Weakness>>,
    #[serde(rename = "cveTags")]
    cve_tags: Option<Vec<CveTag>>,
}

impl CveItem {
    fn get_description(&self) -> String {
        for desc in &self.descriptions {
            if desc.lang == "en" {
                return desc.value.clone();
            }
        }
        if !self.descriptions.is_empty() {
            eprintln!("Failed to find english description, returning first entry");
            return self.descriptions[0].value.clone();
        }
        String::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LangString {
    lang: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_metric_v30: Option<Vec<CvssMetric>>,
}

impl Metrics {
    fn get_v3_base_score(&self) -> Option<f64> {
        if let Some(ref metrics) = self.cvss_metric_v31 {
            if !metrics.is_empty() {
                return Some(metrics[0].cvss_data.base_score);
            }
        }
        if let Some(ref metrics) = self.cvss_metric_v30 {
            if !metrics.is_empty() {
                return Some(metrics[0].cvss_data.base_score);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Weakness {
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
    description: Vec<LangString>,
    #[serde(skip)]
    cwe: Option<Cwe>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cwe {
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CveTag {
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<Tag>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tag {
    value: String,
}

// ============================================================================
// CWE API Models
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
struct CweApiResponse {
    #[serde(rename = "Weaknesses")]
    weaknesses: Option<Vec<CweEntry>>,
}

#[derive(Debug, Clone, Deserialize)]
struct CweEntry {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

// ============================================================================
// Output Vulnerability Format
// ============================================================================

#[derive(Debug, Clone, Serialize)]
struct VulnerabilityDocument {
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize)]
struct Vulnerability {
    cve_id: String,
    cve_description: String,
    package_name: String,
    package_version: String,
    cwe_id: String,
    cwe_name: String,
    affected_file: String,
    affected_function: String,
}

// ============================================================================
// SPDX Parsing
// ============================================================================

#[derive(Debug, Deserialize)]
struct SpdxV3Document {
    #[serde(rename = "@graph")]
    graph: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SpdxV2Document {
    packages: Vec<serde_json::Value>,
}

fn read_spdx_deps(path: &PathBuf) -> Result<Vec<SoftwareDependency>> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read SBOM file: {:?}", path))?;
    
    let doc: SpdxV3Document = serde_json::from_str(&content)
        .context("Failed to parse SPDX v3 document")?;
    
    let mut deps = HashSet::new();
    
    for item in doc.graph {
        if let Some(elements) = item.get("element").and_then(|e| e.as_array()) {
            for elem in elements {
                if let (Some(name), Some(version)) = (
                    elem.get("name").and_then(|n| n.as_str()),
                    elem.get("software_packageVersion").and_then(|v| v.as_str()),
                ) {
                    deps.insert(SoftwareDependency {
                        name: name.to_string(),
                        version: version.to_string(),
                        cves: Vec::new(),
                    });
                }
            }
        }
    }
    
    Ok(deps.into_iter().collect())
}

fn read_spdx2_deps(path: &PathBuf) -> Result<Vec<SoftwareDependency>> {
    let content = std::fs::read_to_string(path)
        .context(format!("Failed to read SBOM file: {:?}", path))?;
    
    let doc: SpdxV2Document = serde_json::from_str(&content)
        .context("Failed to parse SPDX v2 document")?;
    
    let mut deps = HashSet::new();
    
    for pkg in doc.packages {
        if let (Some(name), Some(version_info)) = (
            pkg.get("name").and_then(|n| n.as_str()),
            pkg.get("versionInfo").and_then(|v| v.as_str()),
        ) {
            // Extract version number using regex-like pattern
            if let Some(version) = extract_version(version_info) {
                deps.insert(SoftwareDependency {
                    name: name.to_string(),
                    version,
                    cves: Vec::new(),
                });
            }
        }
    }
    
    Ok(deps.into_iter().collect())
}

fn extract_version(version_str: &str) -> Option<String> {
    // Match pattern like \d+\.\d+(?:\.\d+)*
    // This regex-like extraction looks for sequences like: number.number.number...
    let bytes = version_str.as_bytes();
    let mut start_idx = None;
    let mut end_idx = None;
    
    // Find the start of the version pattern (first digit)
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_digit() {
            start_idx = Some(i);
            break;
        }
    }
    
    if let Some(start) = start_idx {
        let mut i = start;
        let mut last_was_digit = true;
        
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_digit() {
                last_was_digit = true;
                i += 1;
            } else if b == b'.' && last_was_digit && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                // Accept a dot only if it's after a digit and before another digit
                last_was_digit = false;
                i += 1;
            } else {
                // End of version string
                end_idx = Some(i);
                break;
            }
        }
        
        // If we reached the end without breaking, use the end of string
        if end_idx.is_none() {
            end_idx = Some(bytes.len());
        }
        
        if let Some(end) = end_idx {
            let version = &version_str[start..end];
            // Remove trailing dot if any
            let version = version.trim_end_matches('.');
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    
    None
}

fn read_input_sbom(path: &PathBuf) -> Option<Vec<SoftwareDependency>> {
    match read_spdx_deps(path) {
        Ok(deps) => Some(deps),
        Err(e1) => {
            match read_spdx2_deps(path) {
                Ok(deps) => Some(deps),
                Err(e2) => {
                    eprintln!("Error: Could not ingest file: {:?}; {:?}", e1, e2);
                    None
                }
            }
        }
    }
}

// ============================================================================
// CVE Lookup
// ============================================================================

async fn get_cwe(client: &Client, id: &str) -> Option<Cwe> {
    let known_bad_patterns = ["NVD-CWE-Other", "NVD-CWE-noinfo"];
    if known_bad_patterns.contains(&id) {
        return None;
    }
    
    let id_num = id.strip_prefix("CWE-")
        .and_then(|n| n.parse::<u32>().ok())?;
    
    let url = format!("{}/{}", CWE_API_BASE, id_num);
    
    match client.get(&url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                eprintln!("warning: CWE lookup failed: {:?}", resp.status());
                return None;
            }
            
            match resp.json::<CweApiResponse>().await {
                Ok(body) => {
                    if let Some(weaknesses) = body.weaknesses {
                        if let Some(entry) = weaknesses.first() {
                            return Some(Cwe {
                                id: entry.id.clone(),
                                name: entry.name.clone(),
                            });
                        }
                    }
                    eprintln!("CWE Responded empty");
                    None
                }
                Err(e) => {
                    eprintln!("Could not parse data from CWE API: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("CWE lookup request failed: {}", e);
            None
        }
    }
}

async fn get_cves(
    client: &Client,
    mut params: Vec<(String, String)>,
) -> Result<Vec<CveItem>> {
    let mut cves = Vec::new();
    
    loop {
        let response = client
            .get(NVD_API_BASE)
            .query(&params)
            .send()
            .await?
            .error_for_status()?;
        
        let data: NvdApiResponse = response.json().await?;
        
        for vuln_wrapper in data.vulnerabilities {
            let mut cve = vuln_wrapper.cve;
            
            // Enrich weaknesses with CWE data
            if let Some(ref mut weaknesses) = cve.weaknesses {
                for weakness in weaknesses.iter_mut() {
                    for desc in &weakness.description {
                        if desc.lang == "en" && desc.value.contains("CWE") {
                            if let Some(cwe) = get_cwe(client, &desc.value).await {
                                weakness.cwe = Some(cwe);
                            }
                        }
                    }
                }
            }
            
            cves.push(cve);
        }
        
        if cves.len() >= data.total_results {
            break;
        }
        
        // Request next page
        let new_start_index = cves.len();
        println!("Multi-part query: requesting index {}", new_start_index);
        
        // Update or add startIndex parameter
        if let Some(pos) = params.iter().position(|(k, _)| k == "startIndex") {
            params[pos].1 = new_start_index.to_string();
        } else {
            params.push(("startIndex".to_string(), new_start_index.to_string()));
        }
    }
    
    Ok(cves)
}

fn filter_cves(
    cves: Vec<CveItem>,
    min_base_score_v3: f64,
    allow_no_v3_score: bool,
    allow_disputed: bool,
    allow_deferred: bool,
    allow_rejected: bool,
    allow_ids: &[String],
) -> Vec<CveItem> {
    let mut out = Vec::new();
    
    for cve in cves {
        // Check score filtering
        let v3_score = cve.metrics.as_ref().and_then(|m| m.get_v3_base_score());
        
        if !allow_no_v3_score && v3_score.is_none() {
            println!("Filtering {} because CVSS score is too low", cve.id);
            continue;
        }
        
        if let Some(score) = v3_score {
            if score < min_base_score_v3 {
                println!("Filtering {} because is CVSS score is too low", cve.id);
                continue;
            }
        }
        
        // Check disputed tag
        if !allow_disputed {
            let is_disputed = cve.cve_tags.as_ref().map_or(false, |tags| {
                tags.iter().any(|tag| {
                    tag.tags.as_ref().map_or(false, |t| {
                        t.iter().any(|tag_item| tag_item.value == "disputed")
                    })
                })
            });
            
            if is_disputed {
                println!("Filtering {} because it has the disputed tag", cve.id);
                continue;
            }
        }
        
        // Check allow_ids filter
        if !allow_ids.is_empty() && !allow_ids.contains(&cve.id) {
            continue;
        }
        
        // Check status
        if let Some(ref status) = cve.vuln_status {
            let status_lower = status.to_lowercase();
            
            if !allow_deferred && status_lower == "deferred" {
                println!("Filtering {} because it has the deferred status", cve.id);
                continue;
            }
            
            if !allow_rejected && status_lower == "rejected" {
                println!("Filtering {} because it has the rejected status", cve.id);
                continue;
            }
        }
        
        out.push(cve);
    }
    
    out
}

async fn get_cve_by_dep(
    client: &Client,
    dep: &SoftwareDependency,
    min_base_score_v3: f64,
    allow_no_v3_score: bool,
    allow_disputed: bool,
    allow_deferred: bool,
    allow_rejected: bool,
    allow_ids: &[String],
) -> Result<(String, String, Vec<CveItem>)> {
    let params = vec![("virtualMatchString".to_string(), dep.as_query())];
    
    let cves = get_cves(client, params).await?;
    let filtered = filter_cves(
        cves,
        min_base_score_v3,
        allow_no_v3_score,
        allow_disputed,
        allow_deferred,
        allow_rejected,
        allow_ids,
    );
    
    Ok((dep.name.clone(), dep.version.clone(), filtered))
}

async fn dep_lookup(
    deps: &mut [SoftwareDependency],
    min_base_score_v3: f64,
    allow_no_v3_score: bool,
    allow_disputed: bool,
    allow_deferred: bool,
    allow_rejected: bool,
    allow_ids: &[String],
) -> Result<()> {
    let client = Client::new();
    let mut tasks = Vec::new();
    
    for dep in deps.iter() {
        let task = get_cve_by_dep(
            &client,
            dep,
            min_base_score_v3,
            allow_no_v3_score,
            allow_disputed,
            allow_deferred,
            allow_rejected,
            allow_ids,
        );
        tasks.push(task);
    }
    
    let results = futures::future::join_all(tasks).await;
    
    // Create a map to quickly find dependencies by name and version
    let mut dep_map: HashMap<(String, String), &mut SoftwareDependency> = HashMap::new();
    for dep in deps.iter_mut() {
        dep_map.insert((dep.name.clone(), dep.version.clone()), dep);
    }
    
    for result in results {
        match result {
            Ok((name, version, cves)) => {
                if let Some(dep) = dep_map.get_mut(&(name, version)) {
                    dep.cves = cves;
                }
            }
            Err(e) => {
                eprintln!("Lookup failure: {}", e);
            }
        }
    }
    
    Ok(())
}

// ============================================================================
// LLM Integration
// ============================================================================

trait LlmProvider {
    fn get_affected(&self, description: &str) -> Result<(String, String)>;
}

struct GeminiProvider {
    api_key: String,
}

impl GeminiProvider {
    fn new() -> Result<Self> {
        let api_key = std::env::var("GOOGLE_API_KEY")
            .context("GOOGLE_API_KEY environment variable not set")?;
        Ok(Self { api_key })
    }
}

impl LlmProvider for GeminiProvider {
    fn get_affected(&self, description: &str) -> Result<(String, String)> {
        let prompt = format!(
            "The following text describes a CVE. If it specifies which file and function is vulnerable, \
             end your reply with the exact format `{{file name}}:{{function name}}`. Otherwise, if this is \
             not apparent, end your reply with `N/A`. Use thinking and tools if needed, but ensure the final \
             line of your response is exactly the expected format.\n\n{}",
            description
        );
        
        let client = reqwest::blocking::Client::new();
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={}",
            self.api_key
        );
        
        #[derive(Serialize)]
        struct GeminiRequest {
            contents: Vec<Content>,
        }
        
        #[derive(Serialize)]
        struct Content {
            parts: Vec<Part>,
        }
        
        #[derive(Serialize)]
        struct Part {
            text: String,
        }
        
        #[derive(Deserialize)]
        struct GeminiResponse {
            candidates: Vec<Candidate>,
        }
        
        #[derive(Deserialize)]
        struct Candidate {
            content: ResponseContent,
        }
        
        #[derive(Deserialize)]
        struct ResponseContent {
            parts: Vec<ResponsePart>,
        }
        
        #[derive(Deserialize)]
        struct ResponsePart {
            text: String,
        }
        
        let request = GeminiRequest {
            contents: vec![Content {
                parts: vec![Part { text: prompt }],
            }],
        };
        
        let response = client
            .post(&url)
            .json(&request)
            .send()
            .context("Failed to send request to Gemini")?
            .json::<GeminiResponse>()
            .context("Failed to parse Gemini response")?;
        
        if let Some(candidate) = response.candidates.first() {
            if let Some(part) = candidate.content.parts.first() {
                let text = part.text.trim();
                let last_line = text.lines().last().unwrap_or("");
                
                if last_line == "N/A" {
                    return Err(anyhow!("Affected not found"));
                }
                
                let parts: Vec<&str> = last_line.split(':').collect();
                if parts.len() == 2 {
                    return Ok((parts[0].to_string(), parts[1].to_string()));
                }
                
                return Err(anyhow!("Invalid LLM response format"));
            }
        }
        
        Err(anyhow!("Empty Gemini response"))
    }
}

struct OllamaProvider {
    model: String,
    server: String,
}

impl OllamaProvider {
    fn new() -> Result<Self> {
        Ok(Self {
            model: "gemma3".to_string(),
            server: "http://localhost:11434".to_string(),
        })
    }
}

impl LlmProvider for OllamaProvider {
    fn get_affected(&self, description: &str) -> Result<(String, String)> {
        let prompt = format!(
            "The following text describes a CVE. If it specifies which file and function is vulnerable, \
             end your reply with the exact format `{{file name}}:{{function name}}`. Otherwise, if this is \
             not apparent, end your reply with `N/A`. Use thinking and tools if needed, but ensure the final \
             line of your response is exactly the expected format.\n\n{}",
            description
        );
        
        #[derive(Serialize)]
        struct OllamaRequest {
            model: String,
            prompt: String,
        }
        
        #[derive(Deserialize)]
        struct OllamaResponse {
            response: String,
        }
        
        let client = reqwest::blocking::Client::new();
        let url = format!("{}/api/generate", self.server);
        
        let request = OllamaRequest {
            model: self.model.clone(),
            prompt,
        };
        
        let response = client
            .post(&url)
            .json(&request)
            .send()
            .context("Failed to send request to Ollama")?
            .json::<OllamaResponse>()
            .context("Failed to parse Ollama response")?;
        
        let text = response.response.trim();
        let last_line = text.lines().last().unwrap_or("");
        
        if last_line == "N/A" {
            return Err(anyhow!("Affected not found"));
        }
        
        let parts: Vec<&str> = last_line.split(':').collect();
        if parts.len() == 2 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        }
        
        Err(anyhow!("Invalid LLM response format"))
    }
}

struct OpencodeProvider {
    model: String,
}

impl OpencodeProvider {
    fn new() -> Result<Self> {
        Ok(Self {
            model: "openai/gpt-5.3-codex-spark".to_string(),
        })
    }
}

impl LlmProvider for OpencodeProvider {
    fn get_affected(&self, description: &str) -> Result<(String, String)> {
        let prompt = format!(
            "The following text describes a CVE. If it specifies which file and function is vulnerable, \
             end your reply with the exact format `{{file name}}:{{function name}}`. Otherwise, if this is \
             not apparent, end your reply with `N/A`. Use thinking and tools if needed, but ensure the final \
             line of your response is exactly the expected format.\n\n{}",
            description
        );
        
        let permissions = serde_json::json!({
            "webfetch": "allow",
            "websearch": "allow",
            "codesearch": "allow",
        });
        
        let output = Command::new("opencode")
            .arg("run")
            .arg("--agent")
            .arg("build")
            .arg("--model")
            .arg(&self.model)
            .arg(&prompt)
            .env("OPENCODE_PERMISSION", permissions.to_string())
            .output()
            .context("Failed to execute opencode command")?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{}", stderr);
            return Err(anyhow!("Opencode command failed: {}", stderr));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let last_line = stdout.lines().last().unwrap_or("").trim();
        
        if last_line == "N/A" {
            return Err(anyhow!("Affected not found"));
        }
        
        let parts: Vec<&str> = last_line.split(':').collect();
        if parts.len() == 2 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        }
        
        Err(anyhow!("Invalid LLM response format"))
    }
}

fn create_llm_provider(provider_name: &str) -> Result<Box<dyn LlmProvider>> {
    match provider_name {
        "gemini" => Ok(Box::new(GeminiProvider::new()?)),
        "ollama" => Ok(Box::new(OllamaProvider::new()?)),
        "opencode" => Ok(Box::new(OpencodeProvider::new()?)),
        _ => Err(anyhow!("Unknown LLM provider: {}", provider_name)),
    }
}

// ============================================================================
// Output Generation
// ============================================================================

fn cve2vuln(
    cve: &CveItem,
    dep: &SoftwareDependency,
    llm: Option<&Box<dyn LlmProvider>>,
) -> Vec<Vulnerability> {
    let mut affected_file = None;
    let mut affected_function = None;
    
    if let Some(llm_provider) = llm {
        match llm_provider.get_affected(&cve.get_description()) {
            Ok((file, func)) => {
                affected_file = Some(file);
                affected_function = Some(func);
            }
            Err(e) => {
                if e.to_string().contains("Affected not found") {
                    println!("No affected file, func identified in {}.", cve.id);
                } else {
                    println!("Failed to identify affected file, func for {} due to {:?}.", cve.id, e);
                }
            }
        }
    }
    
    let mut weaknesses = HashMap::new();
    
    if let Some(ref weakness_list) = cve.weaknesses {
        for weakness in weakness_list {
            if let Some(ref cwe) = weakness.cwe {
                weaknesses.insert(cwe.id.clone(), cwe.name.clone());
            }
        }
    }
    
    if weaknesses.is_empty() {
        println!("CVE {} does not have a known CWE associated.", cve.id);
        weaknesses.insert("UNKNOWN".to_string(), "UNKNOWN".to_string());
    }
    
    weaknesses
        .into_iter()
        .map(|(cwe_id, cwe_name)| Vulnerability {
            cve_id: cve.id.clone(),
            cve_description: cve.get_description(),
            package_name: dep.name.clone(),
            package_version: dep.version.clone(),
            cwe_id,
            cwe_name,
            affected_file: affected_file.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
            affected_function: affected_function
                .clone()
                .unwrap_or_else(|| "UNKNOWN".to_string()),
        })
        .collect()
}

fn report_deps(deps: &[SoftwareDependency]) {
    for dep in deps {
        println!("\n- {} ({}):", dep.name, dep.version);
        if dep.cves.is_empty() {
            println!("\t No known CVEs");
            continue;
        }
        for cve in &dep.cves {
            let score = cve
                .metrics
                .as_ref()
                .and_then(|m| m.get_v3_base_score())
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "N/A".to_string());
            
            print!("\t- {} (Score: {}).", cve.id, score);
            
            if let Some(ref weaknesses) = cve.weaknesses {
                if !weaknesses.is_empty() {
                    println!(" Weakness(es):");
                    for weakness in weaknesses {
                        if let Some(ref cwe) = weakness.cwe {
                            println!("\t\t- CWE-{} - {}", cwe.id, cwe.name);
                        }
                    }
                } else {
                    println!(" No known CWEs.");
                }
            } else {
                println!(" No known CWEs.");
            }
        }
    }
}

fn output_json(vulns: Vec<Vulnerability>, output_path: &PathBuf) -> Result<()> {
    let doc = VulnerabilityDocument {
        vulnerabilities: vulns,
    };
    
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(output_path, json)?;
    
    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    let mut all_deps = Vec::new();
    
    // Read all SBOM files
    for sbom_path in &args.sbom {
        if let Some(mut deps) = read_input_sbom(sbom_path) {
            all_deps.append(&mut deps);
        }
    }
    
    // Deduplicate dependencies
    let mut unique_deps: Vec<SoftwareDependency> = all_deps
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    
    // Perform CVE lookup
    let min_score = args.min_score.unwrap_or(0.0);
    let allow_no_v3_score = args.min_score.is_none();
    
    dep_lookup(
        &mut unique_deps,
        min_score,
        allow_no_v3_score,
        !args.filter_disputed,
        !args.filter_deferred,
        !args.filter_rejected,
        &args.id,
    )
    .await?;
    
    // Initialize LLM provider if specified
    let llm: Option<Box<dyn LlmProvider>> = if let Some(ref provider) = args.llm_provider {
        match create_llm_provider(provider) {
            Ok(llm) => Some(llm),
            Err(e) => {
                eprintln!("Cannot connect to AI Backend {} due to {}", provider, e);
                None
            }
        }
    } else {
        None
    };
    
    // Convert CVEs to vulnerabilities
    let mut vulnerabilities = Vec::new();
    let mut seen_ids: HashSet<String> = args.id.iter().cloned().collect();
    
    for dep in &unique_deps {
        for cve in &dep.cves {
            seen_ids.remove(&cve.id);
            vulnerabilities.extend(cve2vuln(cve, dep, llm.as_ref()));
        }
    }
    
    // Report not found IDs
    for not_seen in seen_ids {
        println!("No match found for {}", not_seen);
    }
    
    // Determine output path
    let output_path = if let Some(out) = args.out {
        out
    } else if let Some(first_sbom) = args.sbom.first() {
        first_sbom.with_extension("vuln.json")
    } else {
        PathBuf::from("vuln.json")
    };
    
    // Report and output
    report_deps(&unique_deps);
    output_json(vulnerabilities, &output_path)?;
    
    println!("\nOutput written to: {}", output_path.display());
    
    Ok(())
}
