// Copyright (c) 2025 Riverside Research.
// See LICENSE.txt in the repo root for licensing information.

#!/bin/env bash
set -e
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Function to extract the output file from the arguments
get_output_file() {
    for i in "$@"; do
        if [[ "$i" == "-o" ]]; then
            echo "$2"
            return
        fi
        shift
    done
    echo ""
}

# Extract the output file
OUTPUT_FILE=$(get_output_file "$@")

# Allow OUTPUT_FILE to be overridden as RESOLVE_LD_OUTPUT_FILE
OUTPUT_FILE="${RESOLVE_LD_OUTPUT_FILE:-$OUTPUT_FILE}"

# Create a temp file for the link map
# TODO: This might break if user passes -Map option in $@?
lm_file=$(mktemp)
clang -fuse-ld=lld -Wl,-Map=${lm_file} "$@"
# clang -Wl,-Map=${lm_file} "$@"

# Check if an output file was specified

#FIXME: Don't hardcode the output bin path
# ENV variable to cp binary location in run container
# Essentially, we need env variable for cp binary location at build and run
# $SCRIPT_DIR/AnalysisEngine_linkmap.py --in_map $lm_file --out_bin /aria2/src/aria2c

if [ -n "$OUTPUT_FILE" ]; then
    $SCRIPT_DIR/AnalysisEngine_linkmap.py --in_map $lm_file --out_bin $OUTPUT_FILE
else
    echo "RESOLVE WARN: No output file specified. Please use the -o option to specify an output file for linker embedding"
fi
