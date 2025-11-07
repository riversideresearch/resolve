#!/usr/bin/env python3
#
# Copyright (c) 2025 Riverside Research.
# See LICENSE.txt in the repo root for licensing information.

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

USE_COMPRESSION = os.getenv("RESOLVE_IGNORE_COMPRESSION") is None
if USE_COMPRESSION:
    COMPRESSION_SUFFIX = ".zst"
else:
    COMPRESSION_SUFFIX = ""

FACT_SECTION_MAP = [
    (".fact_nodes", "nodes.facts"),
    (".fact_node_props", "nodeprops.facts"),
    (".fact_edges", "edges.facts"),
    (".fact_edge_props", "edgeprops.facts"),
]

# ------------------------------------------------------------------------------
# Binary manipulation: Embed and Extract
# ------------------------------------------------------------------------------

def append_to_section(section: str, input_file: Path, target_bin: Path):
    # get current facts
    facts = subprocess.run(["llvm-objcopy", "--dump-section", f"{section}=/dev/stdout", f"{target_bin}"], capture_output=True, check=True).stdout

    # append new facts
    with input_file.open("rb") as new:
        facts += new.read()

    # replace section with merged facts
    subprocess.run(["llvm-objcopy", "--remove-section", f"{section}", f"{target_bin}"])
    subprocess.run(["llvm-objcopy", "--add-section", f"{section}=/dev/stdin", f"{target_bin}"], input=facts, check=True)

def embed_facts(out_dir: Path, target_bin: Path):
    # compress if needed
    if USE_COMPRESSION:
        subprocess.run([f"zstd", "-f", *(str(out_dir/file) for _, file in FACT_SECTION_MAP)], check=True)

    for section, file in FACT_SECTION_MAP:
        append_to_section(section, out_dir/(file+COMPRESSION_SUFFIX), target_bin)

def extract_facts(out_dir: Path, target_bin: Path):
    for section, file in FACT_SECTION_MAP:
        if subprocess.run([f"objdump -h \"{target_bin}\" | grep \"{section}\""], shell=True).returncode:
            # No section
            contents = b""
        else:
            contents = subprocess.run(["llvm-objcopy", "--dump-section", f"{section}=/dev/stdout", f"{target_bin}"], capture_output=True, check=True).stdout
        with open(out_dir/(file+COMPRESSION_SUFFIX), "ba+") as f:
            f.write(contents)

    # decompress if needed
    if USE_COMPRESSION:
        subprocess.run([f"zstd", "-f", "-d", *(str(out_dir/file)+COMPRESSION_SUFFIX for _, file in FACT_SECTION_MAP)], check=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fact Extraction Helper.")
    parser.add_argument('--in_bin', type=Path, help="Path to the input bin to extract from", required=True)
    parser.add_argument('--out_dir', type=Path, help="Path to the output directory")
    parser.add_argument('--out_bin', type=Path, help="File to embed the output into")

    args = parser.parse_args()

    if not args.out_dir and not args.out_bin:
        parser.error("You must provide either a directory or binary out output facts to.")

    def ingest_facts(out_dir: Path):
        print(f"Using input bin at {args.in_bin}")
        extract_facts(out_dir, args.in_bin)

    def export_facts(out_dir: Path):
        if args.out_bin:
            print(f"Embedding output into {args.out_bin}")
            embed_facts(out_dir, args.out_bin)
    
    if args.out_dir:
        print(f"Using out dir of {args.out_dir}")
        ingest_facts(args.out_dir)
        export_facts(args.out_dir)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            ingest_facts(Path(tmp))
            export_facts(Path(tmp))
