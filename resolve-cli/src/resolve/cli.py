#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import subprocess
import sys

PROGRAM = "resolve"

def find_subcommands():
    """Return a dict of {subcommand: full_path_to_executable}."""
    def is_subcommand(file: Path) -> str | None:
        name = file.name
        if name.startswith(PROGRAM + "-"):
            return name[len(PROGRAM) + 1:]
        else:
            return None

    def files_in_path_dirs(path_dirs: list[Path]):
        for path in path_dirs:
            try:
                yield from path.iterdir()
            except FileNotFoundError:
                continue
    
    subcommands = {}
    path_dirs = [Path(f) for f in os.environ["PATH"].split(os.pathsep)]
    for file in files_in_path_dirs(path_dirs):
        if (sub := is_subcommand(file)) and os.access(file, os.X_OK):
            subcommands[sub] = file
    return subcommands

def main():
    subcommands = find_subcommands()

    parser = argparse.ArgumentParser(prog=PROGRAM)
    parser.add_argument("subcommand", nargs="?", help="Subcommand to run")
    parser.add_argument("args", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    if not args.subcommand:
        print("Available subcommands:")
        for name in sorted(subcommands):
            print(f"  {name}")
        return 0

    # Handle resolve help <subcommand>
    if args.subcommand == "help":
        if not args.args:
            print(f"Usage: {PROGRAM} help <subcommand>")
            return 1
        sub = args.args[0]
        if sub not in subcommands:
            print(f"Unknown subcommand: {sub}")
            return 1
        return subprocess.call([subcommands[sub], "--help"])

    if args.subcommand not in subcommands:
        print(f"Unknown subcommand: {args.subcommand}")
        return 1

    # Dispatch to the external executable
    cmd = [subcommands[args.subcommand]] + args.args
    return subprocess.call(cmd)

if __name__ == "__main__":
    sys.exit(main())
