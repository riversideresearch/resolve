# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import json
from pathlib import Path

REQUIRED_VULNERABILITY_KEYS = {
    "cve-id",
    "cve-description",
    "package-name",
    "package-version",
    "cwe-id",
    "cwe-name",
    "affected-function",
    "affected-file",
    "remediation-strategy",
}

OPTIONAL_VULNERABILITY_KEYS = {
    "undesirable-function",
}

REMEDIATION_STRATEGIES = {
    "exit",
    "recover",
    "sat",
    "widen",
    "continue",
    "none",
    "wrap",
}


def _validate_string_field(vuln: dict, key: str, index: int) -> None:
    value = vuln[key]
    if not isinstance(value, str):
        raise ValueError(f"vulnerabilities[{index}].{key} must be a string")
    if not value:
        raise ValueError(f"vulnerabilities[{index}].{key} must not be empty")


def validate_vulnerabilities_json(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8") as f:
            document = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a top-level JSON object")

    top_level_keys = set(document)
    if top_level_keys != {"vulnerabilities"}:
        extra = sorted(top_level_keys - {"vulnerabilities"})
        missing = sorted({"vulnerabilities"} - top_level_keys)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"unexpected {extra}")
        raise ValueError(
            f"{path} must contain exactly the top-level key 'vulnerabilities': "
            f"{', '.join(details)}"
        )

    vulnerabilities = document["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError(f"{path} field 'vulnerabilities' must be an array")

    allowed_keys = REQUIRED_VULNERABILITY_KEYS | OPTIONAL_VULNERABILITY_KEYS
    for index, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            raise ValueError(f"vulnerabilities[{index}] must be an object")

        keys = set(vuln)
        missing = REQUIRED_VULNERABILITY_KEYS - keys
        extra = keys - allowed_keys
        if missing:
            raise ValueError(
                f"vulnerabilities[{index}] is missing required keys: {sorted(missing)}"
            )
        if extra:
            raise ValueError(
                f"vulnerabilities[{index}] has unexpected keys: {sorted(extra)}"
            )

        for key in REQUIRED_VULNERABILITY_KEYS:
            _validate_string_field(vuln, key, index)
        if "undesirable-function" in vuln:
            _validate_string_field(vuln, "undesirable-function", index)

        cwe_id = vuln["cwe-id"]
        if not cwe_id.isdecimal():
            raise ValueError(
                f"vulnerabilities[{index}].cwe-id must be a numeric string without a CWE- prefix"
            )

        remediation = vuln["remediation-strategy"]
        if remediation not in REMEDIATION_STRATEGIES:
            raise ValueError(
                f"vulnerabilities[{index}].remediation-strategy must be one of "
                f"{sorted(REMEDIATION_STRATEGIES)}"
            )
