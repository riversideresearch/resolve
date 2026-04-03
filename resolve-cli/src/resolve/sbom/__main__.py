import sys

from resolve.cli import subcommand_cli

# Convert current module (resolve or resolve.my_module) into a hypothetical exe for subcommand search
program = __spec__.parent.replace(".", "-").replace("_", "-")
sys.exit(subcommand_cli(program))
