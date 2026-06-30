# vulnerabilities.json

The `vulnerabilities.json` file is an important element of the RESOLVE toolchain, as certain CLI tools can generate it (crash analyzer, input synthesis), and our downstream tools (reachability, remediation) require it.

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

For information on choosing a `cwe-id`, see [supported ids](../../components/resolve-cveassert/#common-mappings).