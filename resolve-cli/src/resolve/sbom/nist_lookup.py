from resolve.sbom.nist_api import CveItem
from resolve.sbom import nist_api
import asyncio
import aiohttp
from aiohttp import ClientSession
import nist_api
import cpe_api
from cpe_api import Cpe

CVE_API_BASE_PATH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API_BASE_PATH = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

async def dep_to_cpe(session: ClientSession, dep: str) -> Cpe:
    """TODO: update to comply with cmake's output format, whatever that is"""
    # for now just do a keyword search
    params = {"keywordSearch": dep}
    async with session.get(CPE_API_BASE_PATH, params=params) as resp:
        resp.raise_for_status()
        json = await resp.json()
    body = cpe_api.JsonSchemaForNvdCommonProductEnumerationCpeApiVersion20.model_validate(json)
    cpes: list[Cpe] = [prod.cpe for prod in body.products]
    if len(cpes) > 1:
        # todo: manual intervention / selection here
        print("WARNING: more than one CPE returned for query, assuming first")
    elif not len(cpes):
        raise FileNotFoundError # TODO custom error type
    return cpes[0]

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

async def get_cves_by_dep(session: ClientSession, dep: str) -> dict[Cpe, list[CveItem]]:
    cpe = await dep_to_cpe(session, dep)
    CVEs = await get_cves(session, {'cpeName': cpe.cpeName})
    return {cpe: CVEs}

async def dep_lookup(deps: list[str]) -> dict[str, list[nist_api.CveItem]]:
    requests: list[Coroutine] = []
    async with ClientSession() as session:
        for dep in deps:
            requests.append(get_cves_by_dep(session, dep))
        results: list[BaseException | dict[Cpe, list[CveItem]]] = await asyncio.gather(*requests, return_exceptions=True)