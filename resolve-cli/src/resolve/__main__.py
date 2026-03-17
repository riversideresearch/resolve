import sys

from .cli import subcommand_cli

def main():
    subcommand_cli(program="resolve")

sys.exit(main())
