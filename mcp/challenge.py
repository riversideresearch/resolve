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

    # Check if build command exists in .resolve_meta
    if "build" not in CHALLENGE_META.get("commands", {}):
        conops = CHALLENGE_META.get("conops", {})
        return {
            "success": False,
            "error": "The 'build' command is not present in .resolve_meta commands section.",
            "details": f"This operation may be disabled or not configured for this challenge. Current conops: {conops}",
            "suggestion": "Check .resolve_meta file and add a 'build' command under the 'commands' section if this operation should be supported."
        }

    if workspace:
        workspaces_dir = os.path.join(CHALLENGE_FOLDER, "workspaces")
        workspace_path = os.path.join(workspaces_dir, workspace)

        if not os.path.exists(workspace_path):
            return {
                "success": False,
                "error": f"Workspace '{workspace}' does not exist at {workspace_path}. Please create it first using create_workspace."
            }

        if not os.path.isdir(workspace_path):
            return {
                "success": False,
                "error": f"Path {workspace_path} exists but is not a directory"
            }

    result = run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["build"], workspace=workspace)
    if "stdout" in result: # soft-cap stdout for context limitations
        result["stdout"] = result["stdout"][:500] + "..." if len(result["stdout"]) > 500 else result["stdout"]
    return result

@mcp.tool()
def build_challenge_instrumented(cwe_id: str, target_function_name: str, affected_file: str = "unknown.c", workspace: str = ""):
    """Builds the challenge problem using the resolve remediation engine, which will remediate a CWE automatically based on the ID. Specify the function name you wish to remediate without return type or parameters. The cwe_id should be a string like '476' for CWE-476. The affected_file is the source file containing the vulnerability (optional, defaults to 'unknown.c'). Optionally specify a workspace name to build from that workspace instead of the default challenge files."""
    # TODO: reject un-implemented CWEs, give better examples for LLMs
    # TODO: can we ever handle multiple vulnerabilities?
    # TODO: what if we already have a vuln.json? - feed forward from .resolve_meta?

    # Check if build remediated command exists in .resolve_meta
    if "build remediated" not in CHALLENGE_META.get("commands", {}):
        conops = CHALLENGE_META.get("conops", {})
        remediation_enabled = conops.get("remediation", False)
        return {
            "success": False,
            "error": "The 'build remediated' command is not present in .resolve_meta commands section.",
            "details": f"Remediation in conops: {remediation_enabled}. This operation may be disabled or not configured for this challenge. Current conops: {conops}",
            "suggestion": "Check .resolve_meta file and add a 'build remediated' command under the 'commands' section if remediation should be supported."
        }

    if workspace:
        workspaces_dir = os.path.join(CHALLENGE_FOLDER, "workspaces")
        workspace_path = os.path.join(workspaces_dir, workspace)

        if not os.path.exists(workspace_path):
            return {
                "success": False,
                "error": f"Workspace '{workspace}' does not exist at {workspace_path}. Please create it first using create_workspace."
            }

        if not os.path.isdir(workspace_path):
            return {
                "success": False,
                "error": f"Path {workspace_path} exists but is not a directory"
            }

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
    # Check if test command exists in .resolve_meta
    if "test" not in CHALLENGE_META.get("commands", {}):
        conops = CHALLENGE_META.get("conops", {})
        return {
            "success": False,
            "error": "The 'test' command is not present in .resolve_meta commands section.",
            "details": f"This operation may be disabled or not configured for this challenge. Current conops: {conops}",
            "suggestion": "Check .resolve_meta file and add a 'test' command under the 'commands' section if testing should be supported."
        }

    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["test"])
    