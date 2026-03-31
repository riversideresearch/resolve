import argparse
import asyncio
import sys
from pathlib import Path
from resolve.sbom.nist_lookup import dep_lookup
from resolve.sbom.dependancies import SoftwareDependancy, read_spdx_deps, MalformedSPDXError

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Identify known CVEs / CWEs for a given SBOM")
    parser.add_argument("-o", "--out", type=Path, help="Path of output file")
    parser.add_argument(
        "-i", "--sbom",
        type=Path,
        help="Path to the input SBOM file.",
        required=True
    )
    parser.add_argument('-E', '--allow-empty-score', action='store_true')
    parser.add_argument('-s', '--min-score', type=float, default=0.0)
    parser.add_argument('-D', '--allow-disputed', action='store_true')
    parser.add_argument('-d', '--allow-deferred', action='store_true')
    parser.add_argument('-R', '--allow-rejected', action='store_true')
    return parser.parse_args(argv)

def output_stdout(deps: list[SoftwareDependancy]):
    for d in deps:
        print(f"\n- {d.name} ({d.version}):")
        if not d.cves:
            print("\t No known CVEs")
            continue
        for cve in d.cves:
            print(f"\t- {cve.id.root} (Score: {cve.metrics.get_v3_base_score() if cve.metrics else 'N/A'}).", end=' ')
            if cve.weaknesses:
                print("Weakness(es):")
                for weakness in cve.weaknesses:
                    print(f"\t\t- {weakness.cwe}")
            else:
                print('No known CWEs.')

def output_json(deps: list[SoftwareDependancy], output_path: Path):
    pass

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv else sys.argv[1:])
    try:
        deps = read_spdx_deps(args.sbom)
    except (FileNotFoundError, MalformedSPDXError) as e:
        print(f"Error: Could not ingest file: {e}")
        return 1

    asyncio.run(dep_lookup(deps, min_base_score_v3=args.min_score, allow_no_v3_score=args.allow_empty_score, allow_disputed=args.allow_disputed, allow_deferred=args.allow_deferred, allow_rejected=args.allow_rejected))
    if args.out:
        output_json(deps, args.out_path)
    else:
        output_stdout(deps)
    return 0