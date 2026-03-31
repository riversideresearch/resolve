import argparse
import asyncio
import sys
from pathlib import Path
from resolve.sbom.lookup import dep_lookup
from resolve.sbom.dependancies import SoftwareDependancy, read_spdx_deps, MalformedSPDXError
from resolve.sbom.schema.nist_api import CWE
from resolve.sbom.schema.vuln_spec import Vulnerability, VulnerabilityDocument
import resolve.sbom.llm as llm
import pdb


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
    parser.add_argument('-L', '--llm-provider', choices=['gemini', 'ollama'], default='gemini')
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

def output_json(vulns: list[Vulnerability], output_path: Path):
    doc = VulnerabilityDocument(vulnerabilities=vulns)
    with open(output_path, 'w') as f:
        f.write(doc.model_dump_json())
    
    
def dep2vulns(dep: SoftwareDependancy, ai: llm.LLM) -> list[Vulnerability]:
    vulns = []
    if not dep.cves:
        return []
    for cve in dep.cves:
        try:
            affected_file, affected_function = ai.get_affected(cve.get_description())
        except llm.LLMError as e:
            print(f"Failed to identify affected file, func for {cve.id} due to {e}. Skipping.")
            continue
        if not cve.weaknesses:
            print(f"CVE {cve.id} does not have a known CWE associated. Skipping.")
            continue
        for weakness in cve.weaknesses:
            cwe = weakness.cwe
            if not isinstance(cwe, CWE):
                print(f"Error: CWE entry is of wrong type! ({type(cwe)}")
                continue
            vuln = Vulnerability(
                cve_id = cve.id,
                cve_description = cve.get_description(),
                package_name=dep.name,
                package_version=dep.version,
                cwe_id=cwe.id,
                cwe_name=cwe.name,
                affected_file=affected_file,
                affected_function=affected_function
            )
            vulns.append(vuln)
    return vulns

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv else sys.argv[1:])
    try:
        deps = read_spdx_deps(args.sbom)
    except (FileNotFoundError, MalformedSPDXError) as e:
        print(f"Error: Could not ingest file: {e}")
        return 1

    asyncio.run(dep_lookup(deps, min_base_score_v3=args.min_score, allow_no_v3_score=args.allow_empty_score, allow_disputed=args.allow_disputed, allow_deferred=args.allow_deferred, allow_rejected=args.allow_rejected))
    match args.llm_provider:
        case 'gemini':
            ai = llm.Gemini()
        case 'ollama':
            ai = llm.Ollama()
        case _:
            print("Err: Unsupported provider",args.llm_provider)
            return 1
    vulnerabilities = []
    for d in deps:
        vulnerabilities.extend(dep2vulns(d, ai))
    if args.out:
        output_json(vulnerabilities, args.out)
    else:
        output_stdout(deps) # TODO convert to vulns
    return 0