# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import os
import json

from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER
from support import run_commands_list

@mcp.resource("resource://challenge_info")
def get_challenge_info() -> dict:
    """Lists the information about the active challenge problem"""
    return CHALLENGE_META

# TODO: should building challenges throw an exception unless it exits 0?
@mcp.tool()
def build_challenge_default_with_facts(workspace: str = "") -> dict:
    """Builds the challenge without any instrumentation and returns the status of the build. This compilation will insert into the binary \"facts\" about its contents that can be analyzed with the reach tool. Optionally specify a workspace name to build from that workspace instead of the default challenge files."""
    # NOTE: consider using a oneshot LLM call to condense stdout into something reasonable?
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["build"], workspace=workspace)

@mcp.tool()
def build_challenge_instrumented(cwe_id: str, target_function_name: str, affected_file: str = "unknown.c", workspace: str = ""):
    """Builds the challenge problem using the resolve remediation engine, which will remediate a CWE automatically based on the ID. Specify the function name you wish to remediate without return type or parameters. The cwe_id should be a string like '476' for CWE-476. The affected_file is the source file containing the vulnerability (optional, defaults to 'unknown.c'). Optionally specify a workspace name to build from that workspace instead of the default challenge files."""
    # TODO: reject un-implemented CWEs, give better examples for LLMs
    # TODO: can we ever handle multiple vulnerabilities?
    # TODO: what if we already have a vuln.json? - feed forward from .resolve_meta?
    
    # write vulnerabilities.json in the challenge folder
    vuln_json_path = os.path.join(CHALLENGE_FOLDER, "resolve_vulnerabilities.json")
    with open(vuln_json_path, "w") as f:
        json.dump({
            "vulnerabilities": [
                {
                    "cwe-id": str(cwe_id),
                    "cwe-name": f"CWE-{cwe_id}",
                    "affected-function": target_function_name,
                    "affected-file": affected_file
                }
            ]
        }, f, indent=4)

    # TODO: RESOLVE_STRATEGY env var    
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["build remediated"], workspace=workspace)

@mcp.tool()
def test_challenge() -> dict:
    """Runs the testing/evaluation commands and returns it's findings. Cross reference the exit code with the challenge info to understand the results."""
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["test"])
    