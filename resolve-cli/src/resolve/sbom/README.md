# Software Bill Of Materials Lookup

This tool cross-references a CMAKE-generated SBOM with NIST's NVD to identify known vulnerabilities, generating a `vulnerabilities.json` with the results.

## Principle of Operation

This tool parses the CMAKE-generated `spdx` SBOM file to identify the name and version number of each dependency.
These are then looked up in NIST's NVD to find any known CVEs.
For each identified CVE, its corresponding CWE(s) is looked up in MITRE's CWE database.
Finally, an LLM is used to extract the vulnerable file and function from the natural language CVE description.

## Usage

### Required Options

  - `-i`, `--sbom`: path to SBOM file
  - `-o`, `--out`: path for output file

### Optional Options
  - `-s`, `--min-score` -- Minimum score for CVEs to be included in report (default 0)
  - `-L`, `--llm-provider` -- LLM provider to use for affected file/function extraction (default Gemini)

### Optional Flags
  - `-E`, `--allow-empty-score` -- Include CVEs that do NOT have 3.0 scores
  - `-D`, `--allow-disputed` -- Include CVEs that are marked disputed
  - `-d`, `--allow-deferred` -- Include CVEs that have been deferred by NIST
  - `-R`, `--allow-rejected` -- Include CVEs that have been rejected by NIST

### Example

```bash
resolve sbom -i example_in.spdx.json -o example_out.json -L ollama
```

## LLM Providers

Currently supported LLM providers are the Gemini API and Ollama.

### Gemini

To use Gemini, the `GEMINI_API_KEY` environmental variable must be set to a valid Google AI Studio API key.

This method uses `gemini-2.5-flash` as the model.

### Ollama

To use Ollama, Ollama must be installed and running on your local system.

This method uses `gemma3` as the model.

## Design Considerations

This codebase is designed to use async networking for its API requests. Real-world projects are expected to have many dependencies,
and the NIST and MITRE APIs are not fast. The async model allows us to dispatch requests in parallelinmprove execution speed. 

Unfortunately, for now, the LLM interactions are synchronous and execute one-at-a-time.

This project uses `pydantic` models to represent the [schemas](schema/README.md) for the [APIs](schema_defs/README.md) it interacts with.
See the relevant documentation for details.
