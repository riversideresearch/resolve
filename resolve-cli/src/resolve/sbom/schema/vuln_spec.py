"""Implementation of JSON schema for resolve vulnerability definitions"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

from resolve.sbom.schema.nist_api import CveId


class VulnerabilityDocument(BaseModel):
    vulnerabilities: list[Vulnerability]


class Vulnerability(BaseModel):
    cve_id: CveId
    cve_description: str
    package_name: str
    package_version: str
    cwe_id: Annotated[str, Field(pattern=r"^(?:\d+)|UNKNOWN$")]
    cwe_name: str
    affected_file: str
    affected_function: str
