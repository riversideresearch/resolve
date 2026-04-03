from __future__ import annotations
import json
import pathlib
from pydantic import BaseModel
from resolve.sbom.schema.nist_api import CveItem

class SoftwareDependancy(BaseModel):
    version: str
    name: str
    cves: list[CveItem] | None = None
    def as_query(self):
        return {"virtualMatchString" : f"cpe:2.3:*:*:{self.name.split(":")[0]}:{self.version}:*:*:*" }

    def set_cves(self, cves: list[CveItem]):
        self.cves = cves

    def __eq__(self, other):
        if not isinstance(other, SoftwareDependancy):
            return False
        return self.name == other.name and self.version == other.version

    def __hash__(self):
        return hash(self.name)^hash(self.version)

class MalformedSPDXError(Exception):
    pass

def read_spdx_deps(filepath: pathlib.Path) -> list[SoftwareDependancy]:
    with open(filepath) as f:
        data = json.loads(f.read())
        ret: set[SoftwareDependancy] = set()
    try:
        graph = data['@graph']
        assert isinstance(graph, list)
    except (KeyError, AssertionError) as e:
        raise MalformedSPDXError from e
    for g in graph:
        elems = g.get("element", [])
        for e in elems:
            name = e.get("name")
            ver = e.get('software_packageVersion')
            if name and ver:
                ret.add(SoftwareDependancy(name=name, version=ver))
    return list(ret)