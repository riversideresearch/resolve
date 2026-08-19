use std::{
    fs::File,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use vers_rs::GenericVersionRange;
use vers_rs::range::VersionRange;
use vers_rs::schemes::semver::SemVer;

use crate::vulnerability::{ReachabilityStatus, VulnerabilityAnalysis};

#[derive(Debug, Deserialize)]
struct VcpkgManifest {
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "version-semver")]
    version_semver: Option<String>,
    #[serde(rename = "version-string")]
    version_string: Option<String>,
    #[serde(rename = "version-date")]
    version_date: Option<String>,
}

impl VcpkgManifest {
    fn into_version(self) -> Option<String> {
        self.version
            .or(self.version_semver)
            .or(self.version_string)
            .or(self.version_date)
    }
}

fn normalize_semver(version: &str) -> String {
    let version = version.trim();
    let suffix_start = version.find(['-', '+']).unwrap_or(version.len());
    let (core, suffix) = version.split_at(suffix_start);
    let components: Vec<&str> = core.split('.').collect();

    if !components.iter().all(|component| {
        !component.is_empty()
            && component
                .chars()
                .all(|character| character.is_ascii_digit())
    }) {
        return version.to_owned();
    }

    match components.len() {
        1 => format!("{core}.0.0{suffix}"),
        2 => format!("{core}.0{suffix}"),
        _ => version.to_owned(),
    }
}

fn normalize_constraint(constraint: &str) -> String {
    let constraint = constraint.trim();
    let Some(version_start) = constraint.find(|character: char| character.is_ascii_digit()) else {
        return constraint.to_owned();
    };
    let (operator, version) = constraint.split_at(version_start);

    format!("{operator}{}", normalize_semver(version))
}

fn normalize_range(vuln_range: &str) -> String {
    let (prefix, constraints) = match vuln_range.strip_prefix("vers:") {
        Some(range) => match range.split_once('/') {
            Some((scheme, constraints)) => (format!("vers:{scheme}/"), constraints),
            None => ("vers:generic/".to_owned(), vuln_range),
        },
        None => ("vers:generic/".to_owned(), vuln_range),
    };
    let constraints = constraints
        .split('|')
        .map(normalize_constraint)
        .collect::<Vec<_>>()
        .join("|");

    format!("{prefix}{constraints}")
}

fn is_vulnerable(vuln_range: &str, actual_version: &str) -> Result<bool, String> {
    let range_spec = normalize_range(vuln_range);
    let range = range_spec
        .parse::<GenericVersionRange<SemVer>>()
        .map_err(|error| format!("failed to parse version range '{vuln_range}': {error}"))?;
    let normalized_version = normalize_semver(actual_version);
    let version = normalized_version
        .parse::<SemVer>()
        .map_err(|error| format!("failed to parse package version '{actual_version}': {error}"))?;

    range
        .contains(&version)
        .map_err(|error| format!("failed to compare package versions: {error}"))
}

fn get_version(src_dir: &Path, package_name: &str) -> Result<(Option<String>, PathBuf), String> {
    let overlay_manifest = src_dir
        .join("vcpkg-overlays")
        .join("ports")
        .join(package_name)
        .join("vcpkg.json");
    let manifest_path = if overlay_manifest.is_file() {
        overlay_manifest
    } else {
        src_dir.join("vcpkg.json")
    };

    let manifest_file = File::open(&manifest_path)
        .map_err(|error| format!("failed to read '{}': {error}", manifest_path.display()))?;
    let manifest: VcpkgManifest = serde_json::from_reader(manifest_file)
        .map_err(|error| format!("failed to parse '{}': {error}", manifest_path.display()))?;

    if manifest.name.as_deref() != Some(package_name) {
        return Ok((None, manifest_path));
    }

    Ok((manifest.into_version(), manifest_path))
}

pub fn populate_version_results(
    sinks: &mut [VulnerabilityAnalysis],
    src_dir: &Path,
) -> Result<(), String> {
    for sink in sinks {
        let (actual_version, manifest_path) = get_version(src_dir, &sink.vuln.package_name)?;
        let Some(actual_version) = actual_version else {
            println!(
                "[REACH] WARNING: Could not find a matching vcpkg package in '{}'.",
                manifest_path.display()
            );
            continue;
        };

        println!(
            "[REACH] Populated package version for '{}' from '{}': {}",
            sink.vuln.package_name,
            manifest_path.display(),
            actual_version
        );

        match is_vulnerable(&sink.vuln.package_version, &actual_version) {
            Ok(true) => println!(
                "[REACH] Package version '{}' is vulnerable according to '{}'.",
                actual_version, sink.vuln.package_version
            ),
            Ok(false) => {
                sink.reachability = ReachabilityStatus::NotVulnerable;
                println!(
                    "[REACH] Package version '{}' is not vulnerable according to '{}'.",
                    actual_version, sink.vuln.package_version
                );
            }
            Err(error) => println!(
                "[REACH] WARNING: Could not compare the package version for '{}': {error}. Reachability analysis will continue.",
                sink.vuln.package_name
            ),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_vulnerable, normalize_range, normalize_semver};

    #[test]
    fn normalizes_short_numeric_versions() {
        assert_eq!(normalize_semver("0"), "0.0.0");
        assert_eq!(normalize_semver("2.21"), "2.21.0");
        assert_eq!(normalize_semver("2.21-beta.1"), "2.21.0-beta.1");
        assert_eq!(normalize_semver("7.10.3"), "7.10.3");
    }

    #[test]
    fn normalizes_each_range_constraint() {
        assert_eq!(
            normalize_range(">= 2.20|<3"),
            "vers:generic/>= 2.20.0|<3.0.0"
        );
        assert_eq!(normalize_range("vers:generic/2.21"), "vers:generic/2.21.0");
    }

    #[test]
    fn compares_short_versions() {
        assert!(is_vulnerable("0", "0").unwrap());
        assert!(is_vulnerable("2.21", "2.21").unwrap());
    }
}
