import json
import argparse
import subprocess
from pathlib import Path


UNDEFINED_SYMBOL_TYPES = {"U", "w", "v"}


def normalize_symbol(symbol):
    symbol = symbol.split("@")[0]

    # special case: find main (could be __libc_start_main)
    if symbol.endswith("main"):
        return "main"

    return symbol


def parse_undefined_symbols(nm_output):
    symbols = {}
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue

        symbol_type, symbol = fields[0], fields[1]
        if symbol_type not in UNDEFINED_SYMBOL_TYPES:
            continue

        normalized_symbol = normalize_symbol(symbol)
        symbols.setdefault(normalized_symbol, set()).add(symbol)
    return symbols


def print_unresolved_symbols(missing_symbols):
    print(f"Missing prototypes ({len(missing_symbols)}):")
    for symbol, raw_symbols in sorted(missing_symbols.items()):
        raw_symbol_list = ", ".join(sorted(raw_symbols))
        print(f"    {symbol} (from: {raw_symbol_list})")

parser = argparse.ArgumentParser(description="Resolve prototype generator")
parser.add_argument("-i", "--input", help="Input binary", required=True)
parser.add_argument("-o", "--output", help="Output file", default="mctoll_prototypes.h")
args = parser.parse_args()

prototype_db = Path(__file__).resolve().with_name("prototypes.json")

with open(prototype_db, "r") as f:
    prototypes_json = json.load(f)
    
    db_size = len(prototypes_json)
    binary_size = 0
    resolved = 0
    missing_symbols = {}

    with open(args.output, "w") as out:
        out.write(f"// Auto-generated resolve prototypes for ELF: {args.input}.\n")
        out.write(f"// Update prototypes.json to map new prototypes as needed. \n\n")

        result = subprocess.run(["nm", "-D", "--undefined-only", args.input], stdout=subprocess.PIPE, text=True)

        prototypes = parse_undefined_symbols(result.stdout)
        binary_size = len(prototypes)

        for proto in sorted(prototypes):
            if proto in prototypes_json:
                resolved += 1
                out.write(f"{prototypes_json[proto]}\n\n")
            else:
                missing_symbols[proto] = prototypes[proto]
                out.write(f"// Prototype for {proto} not found. Please update prototypes.json.\n\n")
            
    print(f"Resolved {resolved}/{binary_size} prototypes from the binary. Database size: {db_size}.")

    if missing_symbols:
        print("WARNING: Not all prototypes were resolved. Please update prototypes.json to include missing prototypes.")
        print_unresolved_symbols(missing_symbols)
        exit(1)
    
    exit(0)
