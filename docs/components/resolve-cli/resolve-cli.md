# Command Line Interface

`resolve-cli` is the primary user interface to **RESOLVE**.

The RESOLVE cli is implemented as a collection of subcommands where `resolve <subcommand> [args...]` runs `resolve-<subcommand> [args...]`

The current subcommands are as follows:

## `reach`

Runs the static reachability analysis.

Inputs:

- vulnerabilities.json
- extracted facts files
- path to reach bin
- source code path, to read vcpkg overlays

Outputs:

- json file with results

## `input-synthesis`

Runs the input synthesis workflow to perform CVE analysis and improvement, (AI enhanced) reachability analysis, and finally input synthesis. 

Inputs: 

- CVE description (consumed by LLM, so any human readable file is appropriate)

Outputs (improve-CVE): 

- `CVE.<ext>` -- improved CVE description (same format as input)
- `necessary_conditions/` -- refined necessary conditions
- `sufficient_conditions/` -- refined sufficient conditions

Outputs (reachability):

- `reachability.md` -- revised reachability analysis
- `conclusion.md` -- one-paragraph summary
- `input-synthesis/` -- synthesized inputs and supporting scripts (if applicable)

## `crash-analyzer`

Runs a crash analysis workflow, agnostic to the specifics of the input.

Inputs: 

- Crash Folder (can contain any relevant files)
- Source Folder (optional, but specifying source code path is useful for matching function symbols and examining logic)

Outputs:

- `vulnerabilities.json` -- for use with resolve tools or deduplication
- `report.md` -- a final explanation of the analysis performed
- `synthesis.md` -- (Internal) Original insights gleaned from cursory analysis
- `thesis.md` -- (Internal) Thesis containing conclusion on crash origin
- `antithesis.md` -- (Internal) Pushback against the thesis

## `sbom`

Searches NVD for known vulnerabilities in an SBOM and generates vulnerabilities.json with the results.

Inputs:

- `<project name>.spdx.json` -- CMAKE-generated software bill of materials (SBOM) in spdx format

Outputs:

- `vulnerabilities.json` -- File listing found vulnerabilities for use by `reach` subcommand.

Options (required):

- `-i`, `--sbom`: path to SBOM file
- `-o`, `--out`: path for output file

Options (optional):

  - See subcommand's README