import argparse
import subprocess
import json
from pathlib import Path

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

    with open(args.output, "w") as out:
        out.write(f"// Auto-generated resolve prototypes for ELF: {args.input}.\n")
        out.write(f"// Update prototypes.json to map new prototypes as needed. \n\n")

        result = subprocess.run(["nm", "-D", "--undefined-only", args.input], stdout=subprocess.PIPE, text=True)

        prototypes = sorted({
            line.strip()[2:].split("@")[0]
            for line in result.stdout.splitlines()
            if line.strip().startswith("U")
        })
        binary_size = len(prototypes)

        for proto in prototypes:

            # special case: find main (could be __libc_start_main)
            if proto.endswith("main"):
                proto = "main"

            if proto in prototypes_json:
                resolved += 1
                out.write(f"{prototypes_json[proto]}\n\n")
            else:
                out.write(f"// Prototype for {proto} not found. Please update prototypes.json.\n\n")
            
    print(f"Resolved {resolved}/{binary_size} prototypes from the binary. Database size: {db_size}.")

    if resolved < binary_size:
        print("WARNING: Not all prototypes were resolved. Please update prototypes.json to include missing prototypes.")
        exit(1)
    
    exit(0)