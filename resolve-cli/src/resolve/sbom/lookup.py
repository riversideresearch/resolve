from typing import Any
from pydantic import ValidationError
import aiohttp
from resolve.sbom.schema.nist_api import CveItem, CWE
from resolve.sbom.schema import nist_api
import asyncio
from aiohttp import ClientSession
from resolve.sbom.dependencies import SoftwareDependancy

CVE_API_BASE_PATH = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def get_cwe(session: aiohttp.ClientSession, id: str):
    known_bad_patterns = ["NVD-CWE-Other", "NVD-CWE-noinfo"]
    if id in known_bad_patterns: 
        return None
    try:
        id_num = int(id.lstrip("CWE-"))
    except ValueError:
        print(f"Could not convert CWE ID {id}")
        return None
    async with session.get(f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{id_num}") as resp:
        if not resp.ok: 
            print("warning: CWE lookup failed: ",resp)
            return None
        body = await resp.json()
        entry = body.get("Weaknesses")
        if not entry or not len(entry):
            print(f"CWE Responded empty: {resp}")
            return None
        entry = entry[0]
        try:
            return CWE(id=entry.get("ID"), name=entry.get("Name"))
        except ValidationError:
            print(f"Could not parse data from CWE API: {entry}")
            return None

async def get_cves(session: aiohttp.ClientSession, params: dict[str, Any]) -> list[CveItem]:
    CVEs: list[nist_api.CveItem] = []
    while True:
        async with session.get(CVE_API_BASE_PATH, params=params) as resp:
            resp.raise_for_status()
            json = await resp.json()
        data = nist_api.JsonSchemaForNvdVulnerabilityDataApiVersion223.model_validate(json)
        for v in data.vulnerabilities:
            cve = v.cve
            if cve.weaknesses:
                for weakness in cve.weaknesses:
                    cwe = None
                    for desc in weakness.description:
                        if desc.lang == 'en' and 'CWE' in desc.value:
                            cwe = await get_cwe(session, desc.value)
                    if isinstance(cwe, CWE):
                        weakness.set_cwe(cwe)
            CVEs.append(cve)

        if len(CVEs) >= data.totalResults:
            break
        ## More results, request next page
        params['startIndex'] = len(CVEs)
        print(f"Multi-part query: requestind index {params['startIndex']}")
    return CVEs

async def get_cve_by_id(session: ClientSession, id: str, **kwargs):
    cves = await get_cves(session, params=dict(cveId=id))
    cves = filter_cves(cves, **kwargs)
    print(len(cves))
    return id, cves


async def get_cve_by_dep(session: ClientSession, dep: SoftwareDependancy, **kwargs):
    cves = await get_cves(session, dep.as_query())
    dep.set_cves(filter_cves(cves, **kwargs))
    return dep

def filter_cves(cves: list[CveItem], min_base_score_v3: float = 0.0, allow_no_v3_score: bool = False, allow_disputed: bool = True, allow_deferred: bool = True, allow_rejected: bool = False):
    out: list[CveItem] = []
    for cve in cves:
        v3_score = cve.metrics.get_v3_base_score() if cve.metrics else None
        if (not allow_no_v3_score and not v3_score) or (v3_score and v3_score < min_base_score_v3):
            print(f"Filtering {cve.id} because is CVSS score is too low")
            continue
        def check_disputed():
            """Return true if a 'disputed' tag is applied to the CVE"""
            if cve.cveTags:
                for tag in cve.cveTags:
                    if tag.tags:
                        for t in tag.tags:
                                if t.value == 'disputed':
                                    return True
            return False
            
        if not allow_disputed and check_disputed():
            print(f"Filtering {cve.id} because it has the disputed tag")
            continue
            
        if isinstance(cve.vulnStatus, str):
            if not allow_deferred and cve.vulnStatus.lower() == 'deferred':
                print(f"Filtering {cve.id} because it has the deferred status")
                continue
            if not allow_rejected and cve.vulnStatus.lower() == 'rejected':
                print(f"Filtering {cve.id} because it has the rejected status")
                continue
        out.append(cve)
    return out

async def dep_lookup(deps: list[SoftwareDependancy], **kwargs) -> list[SoftwareDependancy]:
    requests = []
    async with ClientSession() as session:
        for dep in deps:
            rqst = get_cve_by_dep(session, dep, **kwargs)
            requests.append(rqst)
        results: list[BaseException | SoftwareDependancy] = await asyncio.gather(*requests, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            print(f"Lookup failure: {r}")

    return deps

async def cve_lookup(cve_ids: list[str], **kwargs) -> list[tuple[str, list[CveItem]]]:
    requests = []
    async with ClientSession() as session:
        for id in cve_ids:
            rqst = get_cve_by_id(session, id, **kwargs)
            requests.append(rqst)
        results: list[BaseException | tuple[str, list[CveItem]]] = await asyncio.gather(
            *requests, return_exceptions=True
        )

    for r in results:
        if isinstance(r, Exception):
            print(f"Lookup failure: {r}")

    return [r for r in results if not isinstance(r, BaseException)]
