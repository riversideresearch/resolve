# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import os
import shutil
import re
from pathlib import Path

from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER

def validate_workspace_name(name: str) -> tuple[bool, str]:
    """
    Validates workspace name.
    Returns (is_valid, error_message).
    """
    if not name:
        return False, "Workspace name cannot be empty"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Workspace name can only contain letters, numbers, underscores, and hyphens"
    
    if len(name) > 255:
        return False, "Workspace name is too long (max 255 characters)"
    
    if name in [".", "..", "workspaces"]:
        return False, f"Workspace name '{name}' is reserved"
    
    return True, ""

@mcp.tool()
def create_workspace(name: str) -> dict:
    """Creates a new copy of the challenge problem. This allows you to modify the source code to recompile with either KLEE or remediations (manual or automatic) to test the output."""
    
    is_valid, error_msg = validate_workspace_name(name)
    if not is_valid:
        return {
            "success": False,
            "error": error_msg
        }
    
    workspaces_dir = os.path.join(CHALLENGE_FOLDER, "workspaces")
    os.makedirs(workspaces_dir, exist_ok=True)
    
    workspace_path = os.path.join(workspaces_dir, name)
    
    if os.path.exists(workspace_path):
        return {
            "success": False,
            "error": f"Workspace '{name}' already exists at {workspace_path}"
        }
    
    workspace_targets = CHALLENGE_META.get("workspace targets", [])
    
    if not workspace_targets:
        return {
            "success": False,
            "error": "No 'workspace targets' specified in CHALLENGE_META"
        }
    
    try:
        os.makedirs(workspace_path, exist_ok=True)
        
        copied_targets = []
        failed_targets = []
        
        for target in workspace_targets:
            source_path = os.path.join(CHALLENGE_FOLDER, target)
            dest_path = os.path.join(workspace_path, target)
            
            if not os.path.exists(source_path):
                failed_targets.append(f"{target} (source not found)")
                continue
            
            dest_parent = os.path.dirname(dest_path)
            if dest_parent:
                os.makedirs(dest_parent, exist_ok=True)
            
            if os.path.isdir(source_path):
                shutil.copytree(source_path, dest_path)
            else:
                shutil.copy2(source_path, dest_path)
            
            copied_targets.append(target)
        
        if failed_targets and not copied_targets:
            shutil.rmtree(workspace_path, ignore_errors=True)
            return {
                "success": False,
                "error": f"Failed to copy any targets. Missing: {', '.join(failed_targets)}"
            }
        
        result = {
            "success": True,
            "workspace_name": name,
            "workspace_path": workspace_path,
            "copied_targets": copied_targets,
            "message": f"Workspace '{name}' created successfully with {len(copied_targets)} target(s)"
        }
        
        if failed_targets:
            result["warning"] = f"Some targets could not be copied: {', '.join(failed_targets)}"
        
        return result
        
    except Exception as e:
        if os.path.exists(workspace_path):
            shutil.rmtree(workspace_path, ignore_errors=True)
        
        return {
            "success": False,
            "error": f"Failed to create workspace: {str(e)}"
        }

@mcp.tool()
def list_workspaces() -> dict:
    """Lists all available workspaces in the challenge folder. Returns workspace names and their paths."""
    
    workspaces_dir = os.path.join(CHALLENGE_FOLDER, "workspaces")
    
    if not os.path.exists(workspaces_dir):
        return {
            "success": True,
            "workspaces": [],
            "message": "No workspaces directory found"
        }
    
    try:
        workspaces = []
        for entry in os.listdir(workspaces_dir):
            entry_path = os.path.join(workspaces_dir, entry)
            if os.path.isdir(entry_path):
                workspaces.append({
                    "name": entry,
                    "path": entry_path
                })
        
        workspaces.sort(key=lambda x: x["name"])
        
        return {
            "success": True,
            "workspaces": workspaces,
            "count": len(workspaces),
            "message": f"Found {len(workspaces)} workspace(s)"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to list workspaces: {str(e)}"
        }

@mcp.tool()
def destroy_workspace(name: str) -> dict:
    """Destroys a workspace copy of the challenge problem. This permanently deletes the workspace directory and all its contents."""
    
    is_valid, error_msg = validate_workspace_name(name)
    if not is_valid:
        return {
            "success": False,
            "error": error_msg
        }
    
    workspaces_dir = os.path.join(CHALLENGE_FOLDER, "workspaces")
    workspace_path = os.path.join(workspaces_dir, name)
    
    if not os.path.exists(workspace_path):
        return {
            "success": False,
            "error": f"Workspace '{name}' does not exist at {workspace_path}"
        }
    
    try:
        workspace_path_resolved = os.path.realpath(workspace_path)
        workspaces_dir_resolved = os.path.realpath(workspaces_dir)
        
        if not workspace_path_resolved.startswith(workspaces_dir_resolved + os.sep):
            return {
                "success": False,
                "error": "Invalid workspace path (security violation)"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Path validation failed: {str(e)}"
        }
    
    try:
        shutil.rmtree(workspace_path)
        
        return {
            "success": True,
            "workspace_name": name,
            "message": f"Workspace '{name}' destroyed successfully"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to destroy workspace: {str(e)}"
        }
