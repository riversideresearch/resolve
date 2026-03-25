from resolve.sbom.nist_api import CveItem
from resolve.sbom import nist_api
import asyncio
import aiohttp
from aiohttp import ClientSession
import nist_api
from cpe_api import Cpe, JsonSchemaForNvdCommonProductEnumerationCpeApiVersion20
import sys
import pdb

CVE_API_BASE_PATH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_BASE_PATH = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

async def fuzzy_find_cpe(session: ClientSession, dep: str) -> str:
    """TODO: update to comply with cmake's output format, whatever that is"""
    # for now just do a keyword search
    params = {"keywordSearch": dep}
    async with session.get(CPE_API_BASE_PATH, params=params) as resp:
        resp.raise_for_status()
        json = await resp.json()
    body = JsonSchemaForNvdCommonProductEnumerationCpeApiVersion20.model_validate(json)
    cpes: list[Cpe] = [prod.cpe for prod in body.products]
    if len(cpes) > 1:
        # todo: manual intervention / selection here
        print(f"WARNING: more than one CPE returned for query ({[cpe.cpeName for cpe in cpes]}), assuming first")
    elif not len(cpes):
        raise FileNotFoundError # TODO custom error type
    return cpes[0].cpeName

async def get_cves(session: aiohttp.ClientSession, params: dict[str, str]) -> list[CveItem]:
    CVEs: list[nist_api.CveItem] = []
    while True:
        async with session.get(CVE_API_BASE_PATH, params=params) as resp:
            resp.raise_for_status()
            json = await resp.json()
        data = nist_api.JsonSchemaForNvdVulnerabilityDataApiVersion223.model_validate(json)
        CVEs.extend([item.cve for item in data.vulnerabilities]) # NIST API has unnecessary wrapper around cve object
        if len(CVEs) >= data.totalResults:
            break
        ## More results, request next page
        params['startIndex'] = len(CVEs)
        print(f"Multi-part query: requestind index {params['startIndex']}")
    return CVEs

async def get_cves_by_dep(session: ClientSession, dep: str) -> dict[str, list[CveItem]]:
    cpe = await fuzzy_find_cpe(session, dep)
    CVEs = await get_cves(session, {'cpeName': cpe})
    return {cpe: CVEs}

def filter_cves(cves: list[CveItem], min_base_score_v3: float = 0.0, allow_no_v3_score: bool = False, allow_disputed: bool = True, allow_deferred: bool = True, allow_rejected: bool = False):
    out = []
    if not min_base_score_v3:
        allow_no_v3_score = True
    for cve in cves:
        v3_score = cve.metrics.get_v3_base_score()
        if (not allow_no_v3_score and not v3_score) or (v3_score and v3_score < min_base_score_v3):
            continue
        if not allow_disputed and 'Disputed' in cve.cveTags:
            continue
        if not allow_deferred and cve.vulnStatus.lower() == 'deferred':
            continue
        if not allow_deferred and cve.vulnStatus.lower() == 'rejected':
            continue
        out.append(cve)
    return out

async def dep_lookup(deps: list[str]) -> dict[str, list[nist_api.CveItem]]:
    requests: list[Coroutine] = []
    async with ClientSession() as session:
        for dep in deps:
            requests.append(get_cves_by_dep(session, dep))
        results: list[BaseException | dict[str, list[CveItem]]] = await asyncio.gather(*requests, return_exceptions=True)
    out: dict[str, list[CveItem]] = {}
    for r in results:
        if isinstance(r, dict):
            out.update(r)
        else:
            print(f"WARNING: lookup failed with {r}")
            pdb.set_trace()
    print(f"{len(out)}/{len(deps)} lookups succeeded.")
    return out

# TODO remove, for testing only
def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:]
    res: dict[str, list[CveItem]] = asyncio.run(dep_lookup(args))
    for r in res:
        print(f"{r} Known CVEs:")
        for cve in res[r]:
            print(f"\t- {cve.id.root} [{cve.metrics.get_v3_base_score()}]")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
