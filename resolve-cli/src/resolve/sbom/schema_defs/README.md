# Schema Definitions

This directory contains the JSON schema definitions on which this tool's pydantic models were based.

> [!NOTE]
> The file `spdx-json-schema.json` is not currently in use. The entire SPDX schema contains much more complexity
> than is used by Cmake's SBOM generation (and in turn this CLI), so it was more efficient to hand-parse the parts we care about.
> This schema def is still incuded for reference.
