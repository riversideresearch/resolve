#!/usr/bin/env bash
set -euo pipefail

resolve input-synthesis run-all claude cve.json out/

echo "Pipeline artifacts written to out/"
