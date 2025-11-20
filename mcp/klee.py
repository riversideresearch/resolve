import os
from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER
from support import run_commands_list

@mcp.resource("resource://klee_explanation")
def klee_explanation() -> dict:
    """Gives an explanation for how to use KLEE to generate triggering inputs"""
    return """To use KLEE, you must:
1. create a new workspace
2. edit the main function into being a KLEE harness
3. include the KLEE headers
4. call the KLEE-specific compilation/running tool(s)"""

@mcp.tool()
def compile_klee_bitcode(workspace: str) -> dict:
    """Compiles a KLEE workspace to prepare interpreting."""
    if not workspace:
        return {
            "success": False,
            "error": "Workspace name cannot be empty"
        }
    
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
    
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["build klee"], workspace=workspace)

@mcp.tool()
def run_klee() -> dict:
    """Runs the latest build (please build with KLEE first) to perform input synthesis."""
    return run_commands_list(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["run klee"])
