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

CHALLENGE_META = json.load(open(RESOLVE_CHALLENGE_META))
CHALLENGE_FOLDER = os.path.dirname(RESOLVE_CHALLENGE_META)

# from tools import *
from challenge import *

if __name__ == "__main__":
    mcp.run()
