# Resolve MCP Example

A minimal demonstration problem for the resolve MCP server.

## Overview

This example contains a simple C program with a stack-based buffer overflow vulnerability (CWE-121). It's designed to demonstrate how the resolve MCP server can analyze programs, identify vulnerabilities, and apply automatic remediation using the resolve compiler toolchain.

## The Vulnerability

The program accesses a stack buffer array without bounds checking:

```c
int buffer[10] = { 0 };
int idx = atoi(argv[1]);
buffer[idx] = 42;  // UNSAFE: No bounds checking!
```

Passing an index outside the valid range (0-9) will overflow or underflow the buffer. This pattern uses direct array indexing, which the resolve CVEAssert compiler pass can instrument and protect.

## Project Structure

- `src/main.c` - Simple C program with buffer overflow vulnerability
- `src/CMakeLists.txt` - CMake build configuration
- `Dockerfile` - Docker build using resolve toolchain base image
- `docker-compose.yml` - Docker compose configuration
- `vulnerabilities.json` - CVE/CWE vulnerability metadata (includes `remediation-strategy`)
- `.resolve_meta` - Configuration for the resolve MCP server
- `workspaces/` - Directory for testing remediated versions

## Using with the MCP Server

1. Set the environment variable to point to this example:
   ```bash
   export RESOLVE_CHALLENGE_META=/path/to/mcp/example/.resolve_meta
   ```

2. Start the MCP server:
   ```bash
   fastmcp run main.py --transport http --port 8002
   ```

3. The server will expose tools to:
   - Build the vulnerable program
   - Analyze the vulnerability
   - Generate facts for program analysis
   - Test remediation approaches

From here, use your favorite agentic workflow interface (codex, claude code, etc) to leverage the power of resolve to discover and remediate this vulnerability!

## Building and Testing Locally

### Build Without Instrumentation (Vulnerable)
```bash
docker compose build --no-cache
```

Test with valid index (should succeed):
```bash
docker compose run --rm app /challenge/build/example_app 5
# Exit code: 0
```

Trigger the vulnerability (should crash):
```bash
docker compose run --rm app /challenge/build/example_app 15
# Exit code: 139 (segfault)
```

### Build With Resolve Instrumentation (Protected)
```bash
docker compose build --build-arg RESOLVE_LABEL_CVE=/challenge/vulnerabilities.json --no-cache
```

Test with valid index (should succeed):
```bash
docker compose run --rm app /challenge/build/example_app 5
# Exit code: 0
```

Test with out-of-bounds index (should be caught):
```bash
docker compose run --rm app /challenge/build/example_app 15
# Exit code: 3 (remediation triggered)
```

### Using Docker Compose Profiles
The `docker-compose.yml` includes predefined test cases:

```bash
# Run test with valid input (index 5)
docker compose run --rm test

# Run proof-of-vulnerability with out-of-bounds access (index 15)
docker compose run --rm pov
```
