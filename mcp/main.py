# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import os
import sys
import json
from fastmcp import FastMCP

mcp = FastMCP(
    name="resolve mcp server",
    instructions="This MCP server exposes tools which can be used to compile, instrument, remediate, debug, and input synthesize a challenge problem."
)

RESOLVE_CHALLENGE_META = os.environ.get("RESOLVE_CHALLENGE_META")
if not RESOLVE_CHALLENGE_META:
    print("[ERROR] resolve MCP did not detect RESOLVE_CHALLENGE_META environment variable was set.")
    sys.exit(1)

"""
Reach Tool Path (needed for reachability analysis)
"""
RESOLVE_REACH_BINARY = os.environ.get("RESOLVE_REACH_BINARY")
if not RESOLVE_REACH_BINARY:
    # fallback to ../reach/build/reach relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fallback = os.path.normpath(os.path.join(script_dir, "..", "reach", "build", "reach"))
    if os.path.exists(fallback) and os.path.isfile(fallback):
        RESOLVE_REACH_BINARY = fallback
        print(f"[WARNING] resolve MCP did not detect RESOLVE_REACH_BINARY environment variable. Using {RESOLVE_REACH_BINARY}")
    else:
        print(f"[ERROR] RESOLVE_REACH_BINARY not set and fallback {fallback} does not exist.")
        sys.exit(1)
else:
    if not os.path.exists(RESOLVE_REACH_BINARY) or not os.path.isfile(RESOLVE_REACH_BINARY):
        print(f"[ERROR] RESOLVE_REACH_BINARY is set to {RESOLVE_REACH_BINARY} but that path does not exist or is not a file.")
        sys.exit(1)

"""
Linkmap Tool Path (needed for facts extraction)
"""
RESOLVE_ANALYSIS_ENGINE_FILE = os.environ.get("RESOLVE_ANALYSIS_ENGINE_FILE")
if not RESOLVE_ANALYSIS_ENGINE_FILE:
    # fallback to ../linker/AnalysisEngine_linkmap.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fallback = os.path.normpath(os.path.join(script_dir, "..", "linker", "AnalysisEngine_linkmap.py"))
    if os.path.exists(fallback) and os.path.isfile(fallback):
        RESOLVE_ANALYSIS_ENGINE_FILE = fallback
        print(f"[WARNING] resolve MCP did not detect RESOLVE_ANALYSIS_ENGINE_FILE environment variable. Using {RESOLVE_ANALYSIS_ENGINE_FILE}")
    else:
        print(f"[ERROR] RESOLVE_ANALYSIS_ENGINE_FILE not set and fallback {fallback} does not exist.")
        sys.exit(1)
else:
    if not os.path.exists(RESOLVE_ANALYSIS_ENGINE_FILE) or not os.path.isfile(RESOLVE_ANALYSIS_ENGINE_FILE):
        print(f"[ERROR] RESOLVE_ANALYSIS_ENGINE_FILE is set to {RESOLVE_ANALYSIS_ENGINE_FILE} but that path does not exist or is not a file.")
        sys.exit(1)

"""
Linkmap Tool Path (needed for facts extraction)
"""
RESOLVE_REACH_WRAPPER_FILE = os.environ.get("RESOLVE_REACH_WRAPPER_FILE")
if not RESOLVE_REACH_WRAPPER_FILE:
    # fallback to ../reach-wrapper/reach-wrapper.py
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fallback = os.path.normpath(os.path.join(script_dir, "..", "reach-wrapper", "reach-wrapper.py"))
    if os.path.exists(fallback) and os.path.isfile(fallback):
        RESOLVE_REACH_WRAPPER_FILE = fallback
        print(f"[WARNING] resolve MCP did not detect RESOLVE_REACH_WRAPPER_FILE environment variable. Using {RESOLVE_REACH_WRAPPER_FILE}")
    else:
        print(f"[ERROR] RESOLVE_REACH_WRAPPER_FILE not set and fallback {fallback} does not exist.")
        sys.exit(1)
else:
    if not os.path.exists(RESOLVE_REACH_WRAPPER_FILE) or not os.path.isfile(RESOLVE_REACH_WRAPPER_FILE):
        print(f"[ERROR] RESOLVE_REACH_WRAPPER_FILE is set to {RESOLVE_REACH_WRAPPER_FILE} but that path does not exist or is not a file.")
        sys.exit(1)

CHALLENGE_META = json.load(open(RESOLVE_CHALLENGE_META))
CHALLENGE_FOLDER = os.path.dirname(RESOLVE_CHALLENGE_META)

# from tools import *
from challenge import *
from reachability import *

if __name__ == "__main__":
    mcp.run()
