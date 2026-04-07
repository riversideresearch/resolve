import argparse
import asyncio
import sys
from pathlib import Path
from resolve.sbom.lookup import cve_lookup, dep_lookup
from resolve.sbom.dependencies import (
    SoftwareDependancy,
    read_spdx2_deps,
    read_spdx_deps,
    MalformedSPDXError,
)
from resolve.sbom.schema.nist_api import CWE, CveItem
from resolve.sbom.schema.vuln_spec import Vulnerability, VulnerabilityDocument
import resolve.sbom.llm as llm


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Identify known CVEs / CWEs for a given SBOM")
    parser.add_argument("-o", "--out", type=Path, help="Path of output file")
    parser.add_argument(
        "sbom",
        type=Path,
        nargs="*",
        help="Path to the input SBOM file(s).",
    )
    parser.add_argument(
        "--id",
        nargs="*",
        help="Vulnerability id of interest",
    )
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--filter-deferred", action="store_true")
    parser.add_argument("--filter-disputed", action="store_true")
    parser.add_argument("--filter-rejected", action="store_true")
    parser.add_argument(
        "-L",
        "--llm-provider",
        nargs="?",
        choices=["gemini", "ollama", "opencode"],
        const="opencode",
        default=None,
    )
    return parser.parse_args(argv)

def report_deps(deps: list[SoftwareDependancy]):
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

def report_by_id(vulns_by_id: list[tuple[str, list[CveItem]]]):
    for id, items in vulns_by_id:
        print(f"\n- {id}:")
        if not vulns_by_id:
            print("\t No known CVEs")
            continue
        for cve in items:
            print(
                f"\t- {cve.id.root} (Score: {cve.metrics.get_v3_base_score() if cve.metrics else 'N/A'}).",
                end=" ",
            )
            if cve.weaknesses:
                print("Weakness(es):")
                for weakness in cve.weaknesses:
                    print(f"\t\t- {weakness.cwe}")
            else:
                print("No known CWEs.")


def output_json(vulns: list[Vulnerability], output_path: Path):
    doc = VulnerabilityDocument(vulnerabilities=vulns)

    with open(output_path, 'w') as f:
        f.write(doc.model_dump_json(indent=2))
    
    
def cve2vuln(
    cve: CveItem, dep: SoftwareDependancy | None, ai: llm.LLM | None
) -> list[Vulnerability]:
    affected_file = None
    affected_function = None
    if ai:
        try:
            affected_file, affected_function = ai.get_affected(cve.get_description())
        except llm.AffectedNotFoundError:
            print(f"No affected file, func identifed in {cve.id}.")
        except llm.LLMError as e:
            print(f"Failed to identify affected file, func for {cve.id} due to {e!r}.")

    weaknesses = {}
    if cve.weaknesses is not None:
        weaknesses = {w.cwe.id: w.cwe.name for w in cve.weaknesses if w.cwe is not None}

    if not len(weaknesses):
        print(f"CVE {cve.id} does not have a known CWE associated.")
        weaknesses = {"UNKNOWN": "UNKNOWN"}

    return [
        Vulnerability(
            cve_id=cve.id,
            cve_description=cve.get_description(),
            package_name=dep.name if dep else "UNKNOWN",
            package_version=dep.version if dep else "UNKNOWN",
            cwe_id=id,
            cwe_name=name,
            affected_file=affected_file or "UNKNOWN",
            affected_function=affected_function or "UNKNOWN",
        )
        for id, name in weaknesses.items()
    ]

def read_input_sbom(sbom: Path):
    try:
        return read_spdx_deps(sbom)
    except (FileNotFoundError, MalformedSPDXError) as e1:
        try:
            return read_spdx2_deps(sbom)
        except (FileNotFoundError, MalformedSPDXError) as e2:
            print(f"Error: Could not ingest file: {e1!r}; {e2!r}")
    return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv else sys.argv[1:])
    deps: list[SoftwareDependancy] = []

    for sbom in args.sbom or []:
        if found_deps := read_input_sbom(sbom):
            deps += found_deps

    kwargs = dict(
        min_base_score_v3=args.min_score or 0.0,
        allow_no_v3_score=args.min_score is None,
        allow_disputed=not args.filter_disputed,
        allow_deferred=not args.filter_deferred,
        allow_rejected=not args.filter_rejected,
    )

    asyncio.run(dep_lookup(deps, **kwargs))
    vulns_by_id = asyncio.run(cve_lookup(args.id or [], **kwargs))

    provider = {
        "gemini": llm.Gemini,
        "ollama": llm.Ollama,
        "opencode": llm.Opencode,
    }.get(args.llm_provider, lambda: None)
    try:
        ai: None | llm.LLM = provider()
    except (llm.APIKeyError, llm.APIConnectionError) as e:
        print(f"Cannot connect to AI Backend {args.llm_provider} due to {e.__cause__}")
        ai = None

    vulnerabilities: list[Vulnerability] = []
    for dep in deps:
        assert dep.cves is not None
        for cve in dep.cves:
            vulnerabilities.extend(cve2vuln(cve, dep, ai=ai))
    for _, cves in vulns_by_id:
        for v in cves:
            vulnerabilities.extend(cve2vuln(v, None, ai=ai))

    def get_out():
        if args.out:
            return args.out
        try:
            return args.sbom[0].with_suffix(".vuln.json")
        except (IndexError, TypeError):
            return Path.cwd() / "vuln.json"

    out = get_out()
    report_deps(deps)
    report_by_id(vulns_by_id)
    output_json(vulnerabilities, out)
    return 0
