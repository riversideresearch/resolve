from main import mcp

# @mcp.resource("resource://klee_explanation")
# def klee_explanation() -> dict:
#     """Gives an explanation for how to use KLEE to generate triggering inputs"""
#     return """TODO"""

@mcp.tool()
def create_klee_workspace(name: str|None = None) -> str:
    """Creates a new copy of the challenge problem. This allows you to modify the source code (main function) to turn the program into a KLEE harness, which can be tested with the accompanying functions."""
    pass

@mcp.tool()
def compile_klee_workspace(workspace: str) -> dict:
    """Compiles a KLEE workspace so it can be ran."""
    pass

@mcp.tool()
def run_klee_workspace(workspace: str) -> dict:
    """Runs the challenge problem workspace with KLEE. Before doing this, you should have modified the main function to become a KLEE harness, and compiled the workspace."""
    pass