# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

import os
import sys
import time
import shlex
import subprocess

def run_commands_list(cwd: str, commands: list[str], env=os.environ.copy(), workspace: str = "") -> dict:
    """Runs a list of commands and returns a dictionary with information about their execution. If workspace is specified, sets WORKSPACE environment variable for docker compose builds."""
    outputs = {}
    for command in commands:
        start = time.perf_counter()
        
        parts = shlex.split(command)
        cmd_env = env.copy()
        
        if workspace:
            cmd_env["WORKSPACE"] = workspace
        
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

def run_commands_list_without_capture(cwd: str, commands: list[str], env=os.environ.copy(), workspace: str = "") -> dict:
    """Runs a list of commands and returns a dictionary with information about their execution. If workspace is specified, sets WORKSPACE environment variable for docker compose builds."""
    outputs = {}
    for command in commands:
        start = time.perf_counter()
        
        cmd_env = env.copy()
        if workspace:
            cmd_env["WORKSPACE"] = workspace
        
        res = subprocess.run(command, shell=True, cwd=cwd, env=cmd_env)
        end = time.perf_counter()
        outputs[command] = {
            "exit status": res.returncode,
            "time": end - start
        }
    return outputs
    