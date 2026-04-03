# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import sys

from resolve.cli import subcommand_cli

# Convert current module (resolve or resolve.my_module) into a hypothetical exe for subcommand search
program = __spec__.parent.replace(".", "-").replace("_", "-")
sys.exit(subcommand_cli(program))
