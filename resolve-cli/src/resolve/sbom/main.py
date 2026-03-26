import argparse
import asyncio
import argparse
import sys
from pathlib import Path
from resolve.sbom.nist_lookup import dep_lookup
from resolve.sbom.schema.nist_api import CveItem
from resolve.sbom.schema.vuln_spec import Vulnerability, VulnerabilityDocument

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Identify known CVEs / CWEs for a given SBOM")
    parser.add_argument("output", help="output method / format", choices=("stdout", "json"), default="stdout")
    parser.add_argument("-o", "--out-path", type=Path, help="Path of output file (only applies to non-stdout modes)", default="cwes.json")
    parser.add_argument(
        "-i", "--sbom-path",
        type=Path,
        help="Path to the input SBOM file.",
    )
    parser.add_argument('-k', '--keyword', action='append', dest='deplist', default=[], help="dependancy keyword(s) to search for. Can be specified multiple times.")
    parser.add_argument('-E', '--allow-empty-score', action='store_true')
    parser.add_argument('-s', '--min-score', type=float, default=0.0)
    parser.add_argument('-D', '--allow-disputed', action='store_true')
    parser.add_argument('-d', '--allow-deferred', action='store_true')
    parser.add_argument('-R', '--allow-rejected', action='store_true')
    return parser.parse_args(argv)

def output_text_stdout(results: dict[str, list[CveItem]]):
    for r in results:
            print(f"{r} Known CVEs:")
            for cve in results[r]:
                print(f"\t- {cve.id.root} [{cve.metrics.get_v3_base_score()}]")
                print(f"\t  {[w.cwe for w in cve.weaknesses]}")

def output_json(results: dict[str, list[CveItem]], output_path: Path):
    pass

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv else sys.argv[1:])
    res: dict[str, list[CveItem]] = asyncio.run(dep_lookup(args.deplist, cpe_literal=False, min_base_score_v3=args.min_score, allow_no_v3_score=args.allow_empty_score, allow_disputed=args.allow_disputed, allow_deferred=args.allow_deferred, allow_rejected=args.allow_rejected))
    match args.output:
        case "stdout":
            output_text_stdout(res)
        case "json":
            output_json(res, args.out_path)
    return 0