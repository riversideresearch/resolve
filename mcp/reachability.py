import os
import subprocess

from main import mcp, CHALLENGE_META, CHALLENGE_FOLDER, RESOLVE_ANALYSIS_ENGINE_FILE
from support import run_commands_list, run_commands_list_without_capture

@mcp.tool()
def extract_facts_from_targets() -> dict:
    """Extracts the facts files, containing nodes and edges of a program graph for use with the reach tool, into {CHALLENGE_ROOT}/target/facts. Requires building the program at least once beforehand. If you want unremediated PCG you need to build without instrumentation."""

    run_commands_list_without_capture(CHALLENGE_FOLDER, CHALLENGE_META["commands"]["prepare facts targets"])

    for object in CHALLENGE_META["facts targets"]:
        target_name = object.split('/')[-1]
        os.makedirs(f"{CHALLENGE_FOLDER}/facts/{target_name}/", exist_ok=True)
        subprocess.run([
            "python3",
            RESOLVE_ANALYSIS_ENGINE_FILE,
            "--in_bin", f"{CHALLENGE_FOLDER}/{object}",
            "--out_dir", f"{CHALLENGE_FOLDER}/facts/{target_name}/"
        ], check=True)