# SBOM Lookup Example

Before you can analyze or remediate a vulnerability, you have to *find* one. **RESOLVE**'s SBOM lookup (given a project's software bill of materials) cross-references every dependency against public vulnerability databases and emits a [`vulnerabilities.json`](../concepts/vulnerabilities-json.md), for use with the rest of the toolchain.

This guide walks through running an SBOM lookup with the `resolve` CLI, and has supplemental source code in the [GitHub repository](https://github.com/riversideresearch/resolve/tree/main/examples/sbom/). For the full option reference, see the [SBOM component docs](../components/resolve-cli/sbom.md).

## The SBOM

The input is an [SPDX](https://spdx.dev/) software bill of materials describing your project and its dependencies. CMake can emit one of these as part of a build, so you normally point the tool at the `.spdx.json` your build already produces rather than writing one by hand.

!!! note
    CMake supports the `install(SBOM)` syntax for emitting SPDX since CMake version 4.3, though it is gated behind `CMAKE_EXPERIMENTAL_GENERATE_SBOM`. [See the CMake SBOM docs for more information](https://cmake.org/cmake/help/latest/command/install.html#sbom). 

The only part the lookup cares about is the list of `software_Package` entries, where each contributes a `name` and a `software_packageVersion`. Here are the two dependencies from the example SBOM for a fictional `textkit` application (see the [full file](https://github.com/riversideresearch/resolve/tree/main/examples/sbom/example.spdx.json) for the surrounding SPDX document structure):

```json
"element" : [
    {
        "name" : "fontconfig:fontconfig_project::fontconfig",
        "software_packageVersion" : "2.2.1",
        "spdxId" : "urn:fontconfig::fontconfig#Package",
        "type" : "software_Package"
    },
    {
        "name" : "ZLIB:ZLIB::ZLIB",
        "software_packageVersion" : "1.3.1",
        "spdxId" : "urn:ZLIB::ZLIB#Package",
        "type" : "software_Package"
    }
]
```

That name/version pair is all the lookup needs to query for known vulnerabilities.

!!! note
    **RESOLVE** reads the SPDX 3.0.1 format recent CMake versions generate, and falls back to SPDX 2.x. The dependency version is matched against a CPE (e.g. `cpe:2.3:*:*:fontconfig:2.2.1:*:*:*`), so the version pinned in your SBOM is exactly what gets looked up.

## Running the Lookup

Pass the SBOM file and an output path to [`resolve sbom`](../components/resolve-cli/sbom.md). The optional `-L` flag selects an LLM backend used to pinpoint the affected file and function from each CVE's description:

```bash
resolve sbom example.spdx.json -o vulnerabilities.json -L ollama
```

!!! note
    The lookup queries [NIST's NVD](https://nvd.nist.gov/) and [MITRE's CWE database](https://cwe.mitre.org/) over the network, so a run needs internet access, plus the chosen LLM provider (`gemini`, `ollama`, or `opencode`) installed and authenticated. Without `-L`, the CVEs are still reported, but `affected_file` and `affected_function` come back as `UNKNOWN`.

Under the hood the tool runs four steps (see the [component docs](../components/resolve-cli/sbom.md) for detail):

1. **Parse dependencies**: read each package's name and version out of the SPDX graph.
2. **CVE lookup**: query NVD for known CVEs affecting each dependency version (requests are dispatched in parallel, since real projects have many dependencies).
3. **CWE lookup**: resolve each CVE's weakness class from MITRE's CWE catalog.
4. **Extract the affected symbol**: an LLM reads the CVE's natural-language description to recover the affected file and function.

## Interpreting the Result

The tool writes a [`vulnerabilities.json`](../concepts/vulnerabilities-json.md) with one entry per CVE/CWE it found. For our SBOM, `fontconfig 2.2.1` matches a known off-by-one while `zlib 1.3.1` has no reported vulnerability at that version, so the report looks something like this:

```json
{
  "vulnerabilities": [
    {
      "cve_id": "CVE-2026-34085",
      "cve_description": "fontconfig before 2.17.1 has an off-by-one error in allocation during sfnt capability handling, leading to a one-byte out-of-bounds write, and potentially a crash or code execution. This is in FcFontCapabilities in fcfreetype.c.",
      "package_name": "fontconfig:fontconfig_project::fontconfig",
      "package_version": "2.2.1",
      "cwe_id": "193",
      "cwe_name": "Off-by-one Error",
      "affected_file": "fcfreetype.c",
      "affected_function": "FcFontCapabilities"
    }
  ]
}
```

!!! note
    Results depend on live NVD/MITRE data and on the LLM's extraction, so the exact CVEs, scores, and affected symbols vary over time and between providers. Treat the output as a prioritized starting hypothesis, not a proven bug.

This finding is now in the standard [`vulnerabilities.json`](../concepts/vulnerabilities-json.md) shape, ready for the rest of the pipeline.

!!! tip
    With a `vulnerabilities.json` in hand, you can check whether the flagged function is actually [reachable](reachability.md) from your program's entry point, or instrument a compile-time fix with [remediation](remediation.md).
