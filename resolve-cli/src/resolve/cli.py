# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import argparse
import os
from pathlib import Path
import subprocess

def find_subcommands(program: str):
    """Return a dict of {subcommand: full_path_to_executable}."""
    def is_subcommand(file: Path) -> str | None:
        name = file.name
        if name.startswith(program + "-"):
            return name[len(program) + 1:]
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

def subcommand_cli(program: str):
    """
    Given `program`, presents a cli of the form '`program` <subcommand>', 
    where <subcommand> is any program in PATH of the form '`program`-<subcommand>'

    i.e., if `program` == "resolve" and `resolve-reach` and `resolve-input-synthesis` are binaries in a folder in PATH,
    then this cli would have two subcommands accessed as 'resolve reach' and 'resolve input-syntheis'
    """
    subcommands = find_subcommands(program)

    parser = argparse.ArgumentParser(prog=program, add_help=False)
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

def main():
    import sys
    return subcommand_cli(Path(sys.argv[0]).name)
