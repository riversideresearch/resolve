# RESOLVE MCP

Exposes resolve tools through an MCP server to aid automated program analysis and expedite 0-day remediation.

## Quickstart

### Local

Install [uv](https://docs.astral.sh/uv/getting-started/installation/).

Run `uv run main.py` to install dependencies and start the server (in stdio mode).

If you want to run it in http mode, you can start it with `fastmcp run main.py --transport http --port 8002`

If you want to run it using a MCP-to-OpenAPI proxy (for use with OpenWebUI) you can do so with `uvx mcpo --port 8002 --api-key "top-secret" -- uv run main.py`

To run the program, you must set the `RESOLVE_CHALLENGE_META` environment variable. This value is the full path to the metadata file for the challenge problem the server will operate on.

## Development

### Previewing the API

1. Install `npx`
2. Start the MCP server locally
3. `npx @modelcontextprotocol/inspector`
4. Connect to the MCP server through the inspector webUI
