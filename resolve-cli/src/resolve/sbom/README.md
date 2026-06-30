# Software Bill Of Materials Lookup

This tool cross-references a CMAKE-generated SBOM with NIST's NVD to identify
known vulnerabilities, generating a `vulnerabilities.json` with the results.

**Full documentation:** <https://riversideresearch.github.io/resolve/latest/components/resolve-cli/sbom/>

The `schema/` and `schema_defs/` subdirectories contain the `pydantic` models
for the API and data schemas this tool uses; see their respective READMEs for
those low-level details.
