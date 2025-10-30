import os
import json

from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER
from support import run_commands_list

@mcp.resource("resource://challenge_info")
def get_challenge_info() -> dict:
    """Lists the information about the active challenge problem"""
    return CHALLENGE_META

@mcp.tool()
def build_challenge_vanilla() -> dict:
    """Builds the challenge without any instrumentation and returns the status of the build."""
    # IDEA: use a oneshot LLM call to condense stdout into something reasonable?
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["build"])

@mcp.tool()
def build_challenge_instrumented(cwe_id: str, target_function_name: str, affected_file: str = "unknown.c"):
    """Builds the challenge problem using the resolve remediation engine, which will remediate a CWE automatically based on the ID. Specify the function name you wish to remediate without return type or parameters. The cwe_id should be a string like '476' for CWE-476. The affected_file is the source file containing the vulnerability (optional, defaults to 'unknown.c')."""
    # TODO: reject un-implemented CWEs, give better examples for LLMs
    # TODO: handle multiple vulnerabilities?
    # TODO: what if we already have a vuln.json? - feed forward from .resolve_meta?
    
    # write vulnerabilities.json in the challenge folder (will be copied into Docker context)
    # WARNING: THIS IS A DESTRUCTIVE ACTION IF YOU TRY TO APPLY THIS TO REACHABILITY PROBLEMS
    vuln_json_path = os.path.join(CHALLENGE_FOLDER, "vulnerabilities.json")
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
    # Modify build commands to pass RESOLVE_LABEL_CVE as build arg
    modified_commands = []
    for cmd in CHALLENGE_META["commands"]["build"]:
        if "docker compose build" in cmd:
            cmd = f"{cmd} --build-arg RESOLVE_LABEL_CVE=/challenge/vulnerabilities.json"
        modified_commands.append(cmd)
    
    out = run_commands_list(CHALLENGE_FOLDER, modified_commands)

    # remove the vulnerabilities.json after build
    if os.path.exists(vuln_json_path):
        os.remove(vuln_json_path)

    return out

@mcp.tool()
def test_challenge() -> dict:
    """Runs the testing/evlauation commands and returns it's findings. Cross reference the exit code with the challenge info to understand the results."""
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["test"])