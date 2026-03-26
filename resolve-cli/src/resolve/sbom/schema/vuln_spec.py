"""Implementation of JSON schema for resolve vulnerability definitions"""

from __future__ import annotations

from enum import Enum
from uuid import UUID

from pydantic import NaiveDatetime, BaseModel, ConfigDict, Field, constr

from resolve.sbom.schema.nist_api import CveId, CveItem

class VulnerabilityDocument(BaseModel):
    vulnerabilities: list[Vulnerability]

class Vulnerability(BaseModel):
    cve_id: CveId
    cve_description: str
    package_name: str
    package_version: str
    cwe_id: str 
    cwe_name: str
    affected_file: str
    affected_function: str

    @classmethod
    def from_cve(cve: CveItem, cpe: str):
        def find_desc_en(cve: CveItem) -> str:
            for d in cve.descriptions:
                if d.lang == 'en':
                    return d.value
            return None
        cpe_arr = cpe.split(':')
        return Vulnerability(
            cve.id,
            find_desc_en(cve),
            cpe_arr[4],
            cpe_arr[5],
            cve.weaknesses[0].cwe.id,
            cve.weaknesses[0].cwe.name,
            "", # TODO
            "" # TODO
        )