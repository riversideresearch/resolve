use anyhow::{bail, Context, Result};
use clap::Parser;
use memmap2::MmapMut;
use object::{Object, ObjectSegment, ObjectSymbol};
use phf::phf_map;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

/// CWE -> bit offset mapping for patching
static CWE_PATCHES: phf::Map<u32, &'static [usize]> = phf_map! {
    0u32 => &[0, 1, 2, 3, 4, 5],
    121u32 => &[0],
    122u32 => &[0],
    123u32 => &[0],
    125u32 => &[0],
    131u32 => &[0],
    190u32 => &[4],
    369u32 => &[3],
    476u32 => &[1],
    590u32 => &[2],
    1335u32 => &[5],
    787u32 => &[0],
};

#[derive(Debug, Deserialize)]
struct CweTarget {
    #[serde(rename = "cwe-id")]
    cwe: u32,
    #[serde(rename = "affected-function")]
    function_name: String,
    #[serde(rename = "cve-id")]
    cve_id: String,
}

impl CweTarget {
    /// Get the symbol name to patch (function_name + ".sanmap")
    fn symbol_name(&self) -> String {
        format!("{}.sanmap", self.function_name)
    }
}

#[derive(Debug, Deserialize)]
struct VulnerabilitiesJson {
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    #[serde(rename = "cwe-id")]
    cwe_id: u32,
    #[serde(rename = "affected-function")]
    affected_function: String,
    #[serde(rename = "cve-id")]
    cve_id: String,
    #[serde(default = "default_output")]
    output: String,
    #[serde(default = "default_gated")]
    gated: bool,
}

fn default_output() -> String {
    "inline".to_string()
}

fn default_gated() -> bool {
    true
}

/// Parse CVE descriptions from vulnerabilities.json
fn parse_cve_description(json_path: &PathBuf) -> Result<Vec<CweTarget>> {
    let file = File::open(json_path)
        .with_context(|| format!("Failed to open {}", json_path.display()))?;

    let json_obj: VulnerabilitiesJson = serde_json::from_reader(file)
        .with_context(|| format!("Failed to parse JSON from {}", json_path.display()))?;

    if json_obj.vulnerabilities.is_empty() {
        bail!("[ERROR] No vulnerabilities found.");
    }

    let mut cwe_targets = Vec::new();

    for vuln in json_obj.vulnerabilities {
        if vuln.output == "patch" || vuln.output == "file" {
            println!("Skipping vulnerability with output type: {}", vuln.output);
            continue;
        }

        if !vuln.gated {
            println!("Skipping ungated vulnerability");
            continue;
        }

        cwe_targets.push(CweTarget {
            cwe: vuln.cwe_id,
            function_name: vuln.affected_function,
            cve_id: vuln.cve_id,
        });
    }

    Ok(cwe_targets)
}

/// Find a symbol's virtual address and size in an ELF file
fn find_symbol_offset(data: &[u8], symbol_name: &str) -> Result<(u64, u64)> {
    let obj = object::File::parse(data)
        .with_context(|| "Failed to parse ELF file")?;

    for symbol in obj.symbols() {
        if let Ok(name) = symbol.name() {
            if name == symbol_name {
                let addr = symbol.address();
                let size = symbol.size();
                return Ok((addr, size));
            }
        }
    }

    bail!("[ERROR] Symbol '{}' not found", symbol_name);
}

/// Convert a virtual address to a file offset by scanning PT_LOAD segments
fn find_file_offset(data: &[u8], vaddr: u64) -> Result<u64> {
    let obj = object::File::parse(data)
        .with_context(|| "Failed to parse ELF file")?;

    // For ELF files, segments() returns PT_LOAD segments only
    for segment in obj.segments() {
        let seg_vaddr = segment.address();
        let seg_size = segment.size();
        let (seg_offset, _) = segment.file_range();

        let start = seg_vaddr;
        let end = start + seg_size;

        if start <= vaddr && vaddr < end {
            return Ok(seg_offset + (vaddr - start));
        }
    }

    bail!("Symbol not located in any PT_LOAD segment");
}

/// Set byte at offset in memory-mapped file
fn set_byte(mm: &mut MmapMut, offset: usize, bit: u8) -> (u8, u8) {
    let original = mm[offset];

    if original == bit {
        println!(
            "[INFO] set_bit and original bit match: {} no changes made to binary",
            bit
        );
        return (original, bit);
    }

    mm[offset] = bit;
    (original, bit)
}

/// Patch the value of a symbol inside the ELF binary
fn patch_symbol(elf_path: &PathBuf, symbol_name: &str, cwe: u32, bit: u8) -> Result<()> {
    // Open file for reading and writing
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(elf_path)
        .with_context(|| format!("Failed to open {}", elf_path.display()))?;

    // Memory-map the file
    // SAFETY: We have exclusive write access to the file through OpenOptions.
    // The file will remain valid for the lifetime of the mmap.
    let mut mm = unsafe { MmapMut::map_mut(&file) }
        .with_context(|| format!("Failed to mmap {}", elf_path.display()))?;

    // Find the symbol
    let (symbol_addr, symbol_size) = find_symbol_offset(&mm, symbol_name)
        .with_context(|| format!("Failed to find symbol '{}'", symbol_name))?;

    // Convert virtual address to file offset
    let base_offset = find_file_offset(&mm, symbol_addr)
        .with_context(|| format!("Symbol '{}' not located in any PT_LOAD segment", symbol_name))?;

    // Get patch offsets for this CWE
    let offsets = CWE_PATCHES.get(&cwe)
        .ok_or_else(|| anyhow::anyhow!("[ERROR] Unsupported CWE {}", cwe))?;

    // Apply patches
    for &rel_offset in *offsets {
        if rel_offset as u64 >= symbol_size {
            bail!(
                "[ERROR] Offset {} out of bounds (symbol size = {})",
                rel_offset,
                symbol_size
            );
        }

        let target_offset = base_offset + rel_offset as u64;

        if target_offset >= mm.len() as u64 {
            bail!("[ERROR] Target offset {:#x} out of range", target_offset);
        }

        let (original, modified) = set_byte(&mut mm, target_offset as usize, bit);
        println!(
            "[INFO] Patched {}[{}] @ file offset {:#x}: {:#x} -> {:#x}",
            symbol_name, rel_offset, target_offset, original, modified
        );
    }

    // Flush changes to disk
    mm.flush()
        .with_context(|| format!("Failed to flush changes to {}", elf_path.display()))?;

    Ok(())
}

#[derive(Parser)]
#[command(name = "resolve-remediate")]
#[command(about = "Patch ELF binaries to remediate CVE vulnerabilities")]
struct Cli {
    /// Path to the target ELF binary
    target_bin: PathBuf,

    /// Path to vulnerabilities.json
    cve: PathBuf,

    /// Bit value to set (0-255)
    bit: u8,

    /// Filter by vulnerability ID(s)
    #[arg(long = "id")]
    id: Option<Vec<String>>,
}

fn main() -> Result<()> {
    let args = Cli::parse();

    // Parse CVE descriptions
    let cve_list = parse_cve_description(&args.cve)?;

    // Apply patches
    for cve in cve_list {
        // Filter by ID if specified
        if let Some(ref ids) = args.id {
            if !ids.contains(&cve.cve_id) {
                continue;
            }
        }

        // Patch the symbol - propagate errors like Python version does
        patch_symbol(&args.target_bin, &cve.symbol_name(), cve.cwe, args.bit)?;
    }

    Ok(())
}
