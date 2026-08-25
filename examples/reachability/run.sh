#!/usr/bin/env bash
set -euo pipefail

resolvecc src/main.c -o main

resolve reach -i vulnerabilities.json -f main -o out.json

echo "Reachability report written to out.json"
