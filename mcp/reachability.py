# Copyright (c) 2025 Riverside Research.
# See LICENSE.txt in the repo root for licensing information.

import os
import json
import subprocess

from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER, RESOLVE_ANALYSIS_ENGINE_FILE, RESOLVE_REACH_WRAPPER_FILE, RESOLVE_REACH_BINARY
from support import run_commands_list, run_commands_list_without_capture

@mcp.resource("resource://vulerabilities.json")
def vulnerabilities_json_reference() -> dict:
    """Explains the format of vulnerabilities.json files"""
    return """
vulnerabilities.json files contain one or more vulnerabilities in a codebase (you can be ambiguous if they arent fully explored or known yet).
The format is generally like so:
{
    "vulnerabilities": [
        {
            "cve-id": "CVE-lamartine-001",
            "cve-description": "Lamartine's `Sector::get_polygons` function in `map.cpp` does not access map entities safely, allowing array reads out of bounds. This can lead to crashes or information disclosure.",
            "package-name": "lamartine",
            "package-version": "0.0.1",
            "cwe-id": "125",
            "cwe-name": "Out-of-bounds Read",
            "affected-function": "std::vector<Polygon> Sector::get_polygons(const Map&)",
            "affected-file": "doom/map.cpp"
        },
        {
            "cve-id": "CVE-lamartine-002",
            "cve-description": "Lamartine's `Sidedef::materialize` function in `map.cpp` does not access map entities safely, allowing array reads out of bounds. This can lead to crashes or information disclosure.",
            "package-name": "lamartine",
            "package-version": "0.0.1",
            "cwe-id": "125",
            "cwe-name": "Out-of-bounds Read",
            "affected-function": "void Sidedef::materialize(const Map&)",
            "affected-file": "doom/map.cpp"
        }
    ]
}
    """

@mcp.tool()
def extract_facts_from_targets() -> dict:
    """Extracts the facts files, containing nodes and edges of a program graph for use with the reach tool, into {CHALLENGE_ROOT}/target/facts. Requires building the program at least once beforehand. If you want unremediated PCG you need to build without instrumentation."""

    run_commands_list_without_capture(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["prepare facts targets"])

    results = {}
    for object in CHALLENGE_META["facts targets"]:
        target_name = object.split('/')[-1]
        facts_dir = f"{CHALLENGE_FOLDER}/facts/{target_name}/"
        os.makedirs(facts_dir, exist_ok=True)
        subprocess.run([
            "python3",
            RESOLVE_ANALYSIS_ENGINE_FILE,
            "--in_bin", f"{CHALLENGE_FOLDER}/{object}",
            "--out_dir", facts_dir
        ], check=True)
        
        results[target_name] = {
            "object_path": object,
            "facts_directory": facts_dir,
            "status": "extracted"
        }
    
    return results

@mcp.tool()
def query_reachability(facts_folder: str, vulnerabilities_json: str = f"{CHALLENGE_FOLDER}/vulnerabilities.json", source_dir: str|None = None) -> dict:
    """Takes in a folder of facts about a target and the vulnerabilities.json file, and returns details about whether or not there is a path between the main function and sink functions. Useful for discovering if a vulnerability is reachable, and if so through what candidate paths. If you need to create a vulnerabilties.json, have a look at the reference resource."""
    
    # TODO: --reach flag might be redundant, because reach-wrapper is using it's own guess fallback
    subprocess.run([
        "python3",
        RESOLVE_REACH_WRAPPER_FILE,
        "--input", vulnerabilities_json,
        "--facts", facts_folder,
        "--output", f"{CHALLENGE_FOLDER}/reachability.json",
        "--reach", RESOLVE_REACH_BINARY
        ] + (["--src", source_dir] if source_dir else []), check=True)

    with open(f"{CHALLENGE_FOLDER}/reachability.json", "r") as f:
        return json.load(f)