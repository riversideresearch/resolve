# Software Bill Of Materials Lookup

This tool cross-references a CMAKE-generated SBOM with [NIST's NVD](https://nvd.nist.gov/) to identify known vulnerabilities, generating a [`vulnerabilities.json`](../../concepts/vulnerabilities-json.md) with the results.

!!! tip
    The `vulnerabilities.json` produced here feeds directly into [reachability analysis](../reach.md); see the [reachability example](../../examples/reachability.md) for a walkthrough.

## Principle of Operation

This tool parses the CMAKE-generated [`spdx`](https://spdx.dev/) SBOM file to identify the name and version number of each dependency.
These are then looked up in NIST's NVD to find any known CVEs.
For each identified CVE, its corresponding CWE(s) is looked up in [MITRE's CWE database](https://cwe.mitre.org/).
Finally, an LLM is used to extract the vulnerable file and function from the natural language CVE description.

## Usage

### Arguments

  - `sbom` (positional) -- path to one or more input SBOM file(s)

### Options
  - `-o`, `--out` -- path for the output `vulnerabilities.json` (defaults to `<sbom>.vuln.json`)
  - `-L`, `--llm-provider` `[{gemini,ollama,opencode}]` -- LLM backend used to extract the affected file and function from each CVE description. Omit it to skip extraction (those fields are reported as `UNKNOWN`); passing `-L` with no value uses `opencode`.
  - `--id` `[ID ...]` -- only report the given vulnerability id(s)
  - `--min-score` -- minimum CVSS v3 base score for a CVE to be included. When set, CVEs that have no v3 score are also excluded (by default they are included).

### Filter Flags
By default, disputed, deferred, and rejected CVEs are all included. Pass these to exclude them:

  - `--filter-disputed` -- exclude CVEs marked disputed
  - `--filter-deferred` -- exclude CVEs deferred by NIST
  - `--filter-rejected` -- exclude CVEs rejected by NIST

### Example

```bash
resolve sbom example.spdx.json -o vulnerabilities.json -L ollama
```

See the [SBOM example](../../examples/sbom.md) for an end-to-end walkthrough.

## LLM Providers

Affected-file/function extraction is optional; if you do not pass `-L`, those fields are left as `UNKNOWN` and no LLM is contacted. When enabled, the supported providers are Gemini, Ollama, and Opencode.

### Gemini

To use Gemini, the `GEMINI_API_KEY` environmental variable must be set to a valid Google AI Studio API key.

This method uses `gemini-2.5-flash` as the model.

### Ollama

To use Ollama, Ollama must be installed and running on your local system.

This method uses `gemma3` as the model.

### Opencode

To use Opencode, the `opencode` CLI must be installed and authenticated. This is the provider selected when `-L` is passed with no value.

## Design Considerations

This codebase is designed to use async networking for its API requests. Real-world projects are expected to have many dependencies,
and the NIST and MITRE APIs are not fast. The async model allows us to dispatch requests in parallel to improve execution speed. 

Unfortunately, for now, the LLM interactions are synchronous and execute one-at-a-time.

This project uses `pydantic` models to represent the [schemas](https://github.com/riversideresearch/resolve/blob/main/resolve-cli/src/resolve/sbom/schema/README.md) for the [APIs](https://github.com/riversideresearch/resolve/blob/main/resolve-cli/src/resolve/sbom/schema_defs/README.md) it interacts with.
See the relevant documentation for details.