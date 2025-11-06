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
        parts = shlex.split(command)
        cmd_env = env.copy()
        actual_command = []
        
        for part in parts:
            if '=' in part and not actual_command:
                key, value = part.split('=', 1)
                cmd_env[key] = value
            else:
                actual_command.append(part)
        
        process = subprocess.Popen(
            actual_command,
            cwd=cwd,
            env=cmd_env,
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