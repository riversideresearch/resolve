import os
import sys
from fastmcp import FastMCP

mcp = FastMCP(
    name="resolve mcp server",
    instructions="TODO: INTRODUCE RESOLVE AND HOW IT CAN BE USED"
)

# import os
# import argparse
# parser = argparse.ArgumentParser()
# parser.add_argument("--root", help="Root dir to recursively search for challenge problems inside.")

CHALLENGE_ROOT_PATH = os.environ.get("RESOLVE_MCP_CHALLENGE_ROOT")
if not CHALLENGE_ROOT_PATH:
#     args = parser.parse_args()
#     if args.root is not None:
#         CHALLENGE_ROOT_PATH = args.root
#     else:
#         print("[ERROR] Resolve MCP was not given a CHALLENGE_ROOT_PATH")
    print("[ERROR] Resolve MCP did not detect RESOLVE_MCP_CHALLENGE_ROOT environment variable was set.")
    sys.exit(1)
# print(f"CHALLENGE PATH {CHALLENGE_ROOT_PATH}") # TODO: REMOVEME

from tools import *
from challenges import *

if __name__ == "__main__":
    mcp.run()
