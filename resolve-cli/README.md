# RESOLVE cli

The primary user interface to RESOLVE

## Setup

The overall RESOLVE build/install workflow will place the RESOLVE cli tools in the install prefix.
If a python installation does not already exist there, a pseudo python virtual environment will be created, allowing use like so:

```bash
/opt/resolve/bin/resolve --help
/opt/resolve/bin/resolve input-synthesis setup ...

/opt/resolve/bin/python3 -m resolve.input_synthesis ...
```

```python
#!/opt/resolve/bin/python3
from resolve.reach import Orchestrator;
o = Orchestrator(...).main()
print(o.results)
```

OR use a virtual environment for iterative local development:
```bash
# Get uv if you need it
# curl -LsSf https://astral.sh/uv/install.sh | sh

# create a virtual environment, install deps, install resolve cli
uv sync
# activate the env
source .venv/activate

python3 -m resolve ...
```

## Description

The RESOLVE cli is implemented as a collection of subcommands where `bin/resolve <subcommand> [args...]` runs `resolve-<subcommand> [args...]`

Current subcommands are...
- `reach`
  
  Runs the static reachability analysis.

  Inputs:
  - vulnerabilities.json
  - extracted facts files
  - path to reach bin
  - source code path, to read vcpkg overlays

  Outputs:
  - json file with results

- [`input-synthesis`](resolve-cli/src/resolve/input_synthesis/README.md)

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

- [`sbom`](-src/resolve/sbom/README.md)

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
