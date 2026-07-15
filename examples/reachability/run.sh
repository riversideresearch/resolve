#!/usr/bin/env bash
set -euo pipefail

resolvecc src/main.c -o main

resolve get-facts -i main

resolve reach -i vulnerabilities.json -f main.facts -o out.json

echo "Reachability report written to out.json"
