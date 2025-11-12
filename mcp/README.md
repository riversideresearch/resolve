<!--
  Copyright (c) 2025 Riverside Research.
  LGPL-3; See LICENSE.txt in the repo root for licensing information.
-->

# resolve MCP

Exposes resolve tools through an MCP server to aid automated program analysis and expedite 0-day remediation.

## Quickstart

### Environment Variables

Since resolve MCP accesses a lot of the services, you need to pass a few paths to it as environment variables. You can simplify this by populating `resolve/mcp/.env` with your variables (template provided), running `set -a; source .env; set +a`, and then running the program normally.

The environment variables are as follows:

- `RESOLVE_CHALLENGE_META`: The path to the `.resolve_meta` file in your problem. This controls which challenge problem you are serving through the MCP server. This ***cannot*** be inferred by the program.
- `RESOLVE_REACH_BINARY`: The path to the built `reach` binary (`resolve/reach/build/reach`). This requires you to have `reach` built before running! This ***can*** be inferred as long as you are running this from `resolve/mcp`.
- `RESOLVE_ANALYSIS_ENGINE_FILE`: The path to the `AnalysisEngine_linkmap.py` file. Same as above, it ***can*** be inferred if using the typical project structure.
- `RESOLVE_REACH_WRAPPER_FILE`: The path to the `reach-wrapper.py` file. Same as above, it ***can*** be inferred if using the typical project structure.

### Running

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run `uv run main.py` to install dependencies and start the server (in stdio mode).

If you want to run it in http mode, you can start it with `fastmcp run main.py --transport http --port 8002`

If you want to run it using a MCP-to-OpenAPI proxy (for use with OpenWebUI) you can do so with `uvx mcpo --port 8002 --api-key "top-secret" -- uv run main.py`

See the above list of required and inferred environment variables.

## Development

### Previewing the API

1. Install `npx`
2. Start the MCP server locally
3. `npx @modelcontextprotocol/inspector`
4. Connect to the MCP server through the inspector webUI
