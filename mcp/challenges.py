import os
import glob
import json

from main import mcp, CHALLENGE_ROOT_PATH

@mcp.resource("resource://challenges")
def get_challenges() -> dict:
    """Lists each active challenge problem and how to get more information about each."""
    instances = glob.glob(os.path.join(CHALLENGE_ROOT_PATH, "**", ".resolve_meta"), recursive=True)
    
    out = {}
    for instance in instances:
        name = json.load(open(instance))["name"]
        out[name] = instance

    # TODO: should this throw an exception with 0 CPs?

    return out

@mcp.tool
def get_challenge_info(meta_path: str) -> dict:
    """Lists info about a specific challenge, including how to test it and what outputs to expect."""
    return json.load(open(meta_path))
    # TODO: any post processing here?