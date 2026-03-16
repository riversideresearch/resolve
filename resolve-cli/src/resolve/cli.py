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

    parser = argparse.ArgumentParser(prog=PROGRAM, add_help=False)
    parser.add_argument("subcommand", nargs="?", metavar="subcommand")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("args", nargs=argparse.REMAINDER)

    def show_help():
        parser.print_usage()
        print()
        print("available subcommands:")
        for name in sorted(subcommands):
            print(f"  {name}")

    def show_unknown_subcommand(sub: str):
        parser.print_usage()
        print(f"error: unknown subcommand: {sub}")
        print()
        print("available subcommands:")
        for name in sorted(subcommands):
            print(f"  {name}")


    args = parser.parse_args()

    if args.help or not args.subcommand:
        show_help()
        return 0

    # Handle resolve help <subcommand>
    if args.subcommand == "help":
        if not args.args:
            show_help()
            return 1
        sub = args.args[0]
        if sub not in subcommands:
            show_unknown_subcommand(sub)
            return 1
        return subprocess.call([subcommands[sub], "--help"])

    if args.subcommand not in subcommands:
        show_unknown_subcommand(args.subcommand)
        return 1

    # Dispatch to the external executable
    cmd = [subcommands[args.subcommand]] + args.args
    return subprocess.call(cmd)

if __name__ == "__main__":
    sys.exit(main())
