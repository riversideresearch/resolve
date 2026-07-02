#!/usr/bin/env bash
set -euo pipefail

resolve sbom example.spdx.json -o vulnerabilities.json -L ollama

echo "Vulnerability report written to vulnerabilities.json"
