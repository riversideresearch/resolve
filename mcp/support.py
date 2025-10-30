"""
The first snippet (fully commented out) is the intended version, but
I had to do a hack to get a version which streams to the terminal for
debugging while I'm writing this tool. I intend to revert to the original
version before release.
"""

# import os
# import time
# import shlex
# import subprocess

# def run_commands_list(cwd: str, commands: list[str], env=os.environ.copy()) -> dict:
#     """Runs a list of commands and returns a dictionary with information about their execution."""
#     outputs = {}
#     for command in commands:
#         start = time.perf_counter()
#         res = subprocess.run(shlex.split(command), cwd=cwd, env=env, capture_output=True, text=True)
#         end = time.perf_counter()
#         outputs[command] = {
#             "exit status": res.returncode,
#             "stderr": res.stderr,
#             # "stdout": res.stdout,
#             # TODO: stdout?
#             "time": end - start
#         }
#     return outputs

import os
import sys
import time
import shlex
import subprocess

def run_commands_list(cwd: str, commands: list[str], env=os.environ.copy()) -> dict:
    """Runs a list of commands and returns a dictionary with information about their execution."""
    outputs = {}
    for command in commands:
        start = time.perf_counter()
        
        process = subprocess.Popen(
            shlex.split(command),
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        stdout_lines = []
        stderr_lines = []
        
        for line in process.stdout:
            print(line, end='')
            stdout_lines.append(line)
        
        _, stderr = process.communicate()
        if stderr:
            print(stderr, end='', file=sys.stderr)
            stderr_lines.append(stderr)
        
        end = time.perf_counter()
        outputs[command] = {
            "exit status": process.returncode,
            "stderr": ''.join(stderr_lines),
            "stdout": ''.join(stdout_lines),
            "time": end - start
        }
    return outputs