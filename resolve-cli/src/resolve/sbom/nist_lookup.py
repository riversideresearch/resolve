from resolve.sbom.nist_api import CveItem
from resolve.sbom import nist_api
import asyncio
import aiohttp
import nist_api

BASE_PATH = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def get_cves(session: aiohttp.ClientSession, params: dict[str, str]) -> list[CveItem]:
    CVEs: list[nist_api.CveItem] = []
    while True:
        async with session.get(BASE_PATH, params=params) as resp:
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

async def get_cves_by_cpe(session: aiohttp.ClientSession, cpe: CPE) -> dict[CPE, list[CveItem]]:
    CVEs = await get_cves(session, cpe.as_param())
    return {cpe: CVEs}

async def dep_lookup(deps: list[CPE]) -> dict[str, list[nist_api.CveItem]]:
    requests: list[Coroutine] = []
    async with aiohttp.ClientSession() as session:
        for dep in deps:
            # todo: fuzzy search?
            requests.append(get_cves_by_cpe(session, dep.as_param()))
    results: list[BaseException | dict[CPE, list[CveItem]]] = await asyncio.gather(*requests, return_exceptions=True)