# vulnerabilities.json

The `vulnerabilities.json` file is an important element of the **RESOLVE** toolchain, as certain CLI tools can generate it ([crash analysis](../components/resolve-cli/crash-analysis.md), [input synthesis](../components/resolve-cli/input-synthesis.md)), and our downstream tools ([reachability](../components/reach.md), [remediation](../components/resolve-cveassert.md)) require it.

!!! note
    An [SBOM lookup](../components/resolve-cli/sbom.md) can also generate a `vulnerabilities.json` from a project's software bill of materials.

The basic format is like this:

```json
{
    "vulnerabilities": [
        {
            // required fields:
            "cve-id": "String", // any identifier you want
            "cwe-id": "Int in String",
            "affected-function": "String",
            "affected-file": "String",

            // defaulting fields:
            "remediation-strategy" : "widen | sat | exit | continue | recover | none | wrap", // default: continue
            "output": "inline | patch | toggle", // default: inline
            "gated": bool, // default: false

            // optional fields:
            "cve-description": "String",
            "package-name": "String",
            "package-version": "Int in String",
            "cwe-name": "String",
            "undesirable-function": "String", // if set, operation masking is applied
        },
    ]
}
```

!!! note
    Even some of the "required" fields are not actually consumed by certain tools, but this is the minimum set that are required for compatibility with all **RESOLVE** tools. For example, CVEAssert does not care if you provide a `cve-id`.  

For information on choosing a `cwe-id`, see [supported ids](../components/resolve-cveassert.md#common-mappings).
