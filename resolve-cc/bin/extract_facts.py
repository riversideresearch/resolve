#!/usr/bin/env python3
#
# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
import subprocess
import tempfile
from pathlib import Path
from shutil import rmtree
from typing import List, TextIO
from sys import exit

USE_COMPRESSION = os.getenv("RESOLVE_IGNORE_COMPRESSION") is None
if USE_COMPRESSION:
    COMPRESSION_SUFFIX = ".zst"
else:
    COMPRESSION_SUFFIX = ""

FACT_SECTION_MAP = [
    (".facts", "facts.facts"),
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

def link_facts(out_dir: Path, fact_files: List[TextIO], do_cleanup: bool, do_overwrite: bool):
    tmp_out_dir = Path.cwd() / ".tmp_resolve"
    dst_file = Path.cwd() / out_dir / "facts.facts"
    
    if(os.path.exists(dst_file) and os.path.getsize(dst_file) > 0):
        if(do_overwrite):
            print(f"Pruning directory '{out_dir}'")
            rmtree(out_dir)
        else:
            print(f"[ERROR] An output file {tmp_out_dir} already exists - abort\n\tHint: specify (-f / --force) to OVERWRITE and proceed regardless")
            return 1
    if(not os.path.exists(tmp_out_dir)):
            os.makedirs(tmp_out_dir)
    if(not os.path.exists(out_dir)):
        os.makedirs(out_dir)

    for bin in fact_files:
        bin_name = bin.name
        if(not os.path.exists(bin_name) or os.path.getsize(bin_name) <= 0):
            print(f"[WARNING] Skipping unknown file {bin_name}")
            continue
        print(f"Target {bin_name}: link facts")

        bin_out_dir = tmp_out_dir / os.path.basename(bin_name)
        if(not os.path.exists(bin_out_dir)):
            os.makedirs(bin_out_dir)

        extract_facts(bin_out_dir, bin_name)

        with open(bin_out_dir / "facts.facts", 'r') as src:
            s = src.read()
        with open(dst_file, 'a') as dst:
            dst.write(s)

        if do_cleanup:
            try:
                rmtree(bin_out_dir)
                print(f"Appended {bin_name} and removed tmp dir {bin_out_dir}")
            except Exception as e:
                print(f"[Error] Unexpected exception while removing '{bin_out_dir}': {e.strerror}")
        print("==========")
        
    if do_cleanup:
        try:
            os.rmdir(tmp_out_dir)
        except FileNotFoundError:
            print(f"[Error]: the temp directory '{tmp_out_dir}' cannot be removed at this time: {FileNotFoundError.strerror}")
        except Exception as e:
            print(f"[Error]: Unexpected exception while removing assumed empty directory '{tmp_out_dir}': {e.strerror}")
    print("Finished linking fact files.")
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fact Extraction Helper.")
    parser.add_argument('--in_bin', type=Path, help="Path to the input bin to extract from")#, required=True)
    parser.add_argument('--out_dir', type=Path, help="Path to the output directory")
    parser.add_argument('--out_bin', type=Path, help="File to embed the output into")
    parser.add_argument('--fact_files', type=argparse.FileType('r'), nargs='+', help="Glob of multiple input binaries to extract and combine")
    parser.add_argument('--no_fact_files_cleanup', action='store_false', dest='fact_files_cleanup', help="Do not remove copies of fact files after linking")
    parser.add_argument('-f', '--force', action='store_true', dest='force', help="Remove old fact linkage if one is detected")

    args = parser.parse_args()

    if not args.out_dir and not args.out_bin:
        parser.error("You must provide either a directory or binary out output facts to.")

    if args.fact_files:
        if not args.out_dir:
            parser.error("You must provide an output directory when grouping fact files.")
        if args.out_bin:
            parser.error("Grouping multiple --fact_files does not support embedding to binaries")

        # Specifying fact_files will not attempt in_bin operations - early-out
        exit(link_facts(args.out_dir, args.fact_files, args.fact_files_cleanup, args.force))
    else:
        # Cover for removing --in_bin required=True
        if not args.in_bin:
            parser.error("You must specify either one (--in_bin) or multiple (--fact_files) input binaries")

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
