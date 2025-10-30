import os
import sys
import json
from fastmcp import FastMCP

mcp = FastMCP(
    name="resolve mcp server",
    instructions="TODO: INTRODUCE RESOLVE AND HOW IT CAN BE USED"
)

RESOLVE_CHALLENGE_META = os.environ.get("RESOLVE_CHALLENGE_META")
if not RESOLVE_CHALLENGE_META:
    print("[ERROR] Resolve MCP did not detect RESOLVE_CHALLENGE_META environment variable was set.")
    sys.exit(1)

CHALLENGE_META = json.load(open(RESOLVE_CHALLENGE_META))
CHALLENGE_FOLDER = os.path.dirname(RESOLVE_CHALLENGE_META)

# from tools import *
from challenge import *

if __name__ == "__main__":
    mcp.run()
