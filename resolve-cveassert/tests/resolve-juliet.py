#!/usr/bin/env python3
from signal import Signals
from typing import Mapping
import argparse
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from subprocess import CalledProcessError, CompletedProcess

juliet_testsuite_root = Path(__file__).parent
juliet_testcases_dir = juliet_testsuite_root / "testcases"
juliet_testcase_support_headers = juliet_testsuite_root / "testcasesupport"

resolve_cc = "resolvecc"


def compile_io_c(out_dir: Path):
    """Compile io.c into obj file for linking

    Returns the path to the compiled object file
    """
    io_file = juliet_testcase_support_headers / "io.c"
    obj_file = out_dir / "io.o"

    if obj_file.exists():
        return obj_file

    subprocess.run(
        [
            "clang",
            "-c",
            "-I",
            str(juliet_testcase_support_headers),
            str(io_file),
            "-o",
            str(obj_file),
        ],
        check=True,
    )

    return obj_file

def find_matching_file_contents(source_files: list[Path], pattern: re.Pattern) -> list[tuple[Path, re.Match]]:
    """ 
    Finds the first match group of `pattern` in each file in `source_files`
    Returns a list of pairs of the form (<file-path>, match)
    Files with no matches are not included in the return file 
    """
    matched_files = []

    for path in source_files:
        if not path.is_file():
            continue

        # open the file for reading
        with path.open("r") as f:
            # scan each line
            for line in f:
                match = pattern.search(line)
                if match:
                    # add the path and the match to the list
                    matched_files.append((path, match))
                    break # stop scanning file once matched 

    return matched_files

def findBad(source_files: list[Path]) -> list[tuple]:
    """ 
    Given a list of source files, return the files
    that contain a CWE bad function defintion and the function name.
    """
    bad_pattern = re.compile(
        r"^\s*(?:static\s+)?(?:void|int)\s+(\w+_bad)\s*\(",
    re.VERBOSE)

    # Function name is group(1) match
    bad_files = [
        (path, match.group(1))
        for path, match in find_matching_file_contents(source_files, bad_pattern)
    ]

    return bad_files

def findGood(source_files: list[Path]) -> list[tuple]:
    """
    Given a list of source files, return the files
    that contain a CWE good function defintion.
    """ 

    cwe_good_pattern = re.compile(
    r"^\s*(?:static\s+)?(?:void|int)\s+(\w+_?good)\s*\(",
    re.VERBOSE)

    # Find G\d+B\d* (G2B, G2B1, G2B2)
    # Find B\d+G\d* (B2G, B2G1, B2G2)
    good_g_b_flow_pattern = re.compile(r"""
    ^\s*
    (?:static\s+)?                      # optional static and return type
    (?:void|int)\s+                     # optional return value type 
    (good(?:G\d+B\d*|B\d+G\d*))         # capture just 'goodG2B*' or goodB2G*' 
    \s*\(                               # opening parenthesis
    """, re.VERBOSE)

    matching_cwe_pattern_files = [
        (path, match.group(1))
        for path, match in find_matching_file_contents(source_files, cwe_good_pattern)
    ]
    matching_g_b_pattern_files = [
        (path, match.group(1))
        for path, match in find_matching_file_contents(
            source_files, good_g_b_flow_pattern
        )
    ]
    
    # Return both lists as a combined list
    return matching_cwe_pattern_files + matching_g_b_pattern_files 

@dataclass
class CWETestDir:
    id: int
    dir: Path
    name: str

    @classmethod
    def from_dir(cls, dir: Path) -> "CWETestDir | None":
        """Create a `CWETestDir` from a path of the form CWEXXX_*"""
        match = re.search(r"^CWE(\d+)_(.*)", dir.name)
        if match is None:
            return None
        id, name = match.groups()
        return cls(id=int(id), name=name, dir=dir)

    @classmethod
    def all_in_dir(cls, dir: Path):
        """Find all `CWETestDir`'s in `dir

        Skip directories that don't match.
        """
        for dir in dir.iterdir():
            # TODO: Warn if no match
            if test := CWETestDir.from_dir(dir):
                yield test

    def iterdir(self):
        """Iterate over sources in `self.dir`

        Some juliet testsuite CWE directories have their source files
        grouped into subdirs while others just contain all the src files.
        """
        for source_path in self.dir.iterdir():
            if source_path.is_dir():
                yield from source_path.iterdir()
            else:
                yield source_path

    def collect_tests(self) -> Mapping[str, list[Path]]:
        """Collect tests in `self`

        Each test may contain multiple sources.
        """
        # Map test name to all of its source files
        test_src_files: defaultdict[str, list[Path]] = defaultdict(list)

        # Group source files according to name (words followed by an index)
        for source_path in self.iterdir():
            # Extract group key from stem
            stem = source_path.stem
            match = re.search(r"^(.*_\d+)", stem)

            if not match:
                # TODO: Warn if no match
                continue

            testcase_name = match.group(1)
            test_src_files[testcase_name].append(source_path)

        return test_src_files


@dataclass
class CWETest:
    id: int
    name: str
    source_paths: list[Path]

    def get_cve_description(self):
        """
        Creates a CVE description by locating affected functions
        within files per a particular test
        """

        affected_functions = findBad(self.source_paths) + findGood(self.source_paths)

        if len(affected_functions) == 0:
            return None

        # Build JSON
        vulnerabilities = [
            {
                "cwe-id": str(self.id),
                "affected-function": func,
                "affected-file": str(file),
                "remediation-strategy": "exit",
            }
            for file, func in affected_functions
        ]

        return {"vulnerabilities": vulnerabilities}


@dataclass
class Result:
    """The outcome of a single test

    Possible outcomes: Exit, Signal, CompilationFailure
    """


@dataclass
class ResultExit(Result):
    exit_code: int


@dataclass
class ResultSignal(Result):
    signal: int

    def get_signal_name(self):
        return Signals(self.signal).name


@dataclass
class ResultCompilationFailure(Result):
    called_process: CompletedProcess[str]


def do_test(test: CWETest, io_obj: Path, out_dir: Path) -> Result:
    # Binary path to compiled testcase executable
    testcase_exe_path = out_dir / test.name

    # Create the JSON-formatted CVE description
    cve_description_path = out_dir / f"{test.name}.json"
    with cve_description_path.open("w") as f:
        json.dump(test.get_cve_description(), f, indent=4)

    # Set the environment variable
    env_var = os.environ.copy()
    env_var["RESOLVE_LABEL_CVE"] = str(cve_description_path)

    compile_cmd = [
        resolve_cc,
        "-DOMITGOOD",
        "-DINCLUDEMAIN",
        "-I",
        str(juliet_testcase_support_headers),
        *[str(f) for f in test.source_paths],
        str(io_obj),
        "-o",
        str(testcase_exe_path),
    ]

    # Compile source files with CVE description
    compile_process = subprocess.run(
        compile_cmd, env=env_var, capture_output=True, text=True
    )

    if compile_process.returncode != 0:
        return ResultCompilationFailure(compile_process)

    # Execute the compiled binary
    executed_binary = subprocess.run(
        [str(testcase_exe_path)], input="", capture_output=True, timeout=30, text=True
    )

    match executed_binary.returncode:
        case i if i > 0:
            return ResultExit(i)
        case signal:
            return ResultSignal(-signal)


def test_cwe(test_dir: CWETestDir, io_obj: Path, out_dir: Path):
    tests = [
        CWETest(test_dir.id, name, source_paths)
        for name, source_paths in test_dir.collect_tests().items()
    ]

    results = [do_test(test, io_obj, out_dir) for test in tests]

    correct_exit_code = 0
    incorrect_exit_code = 0
    zero_exit_code = 0
    unexpected_exit_code = 0
    failed_signal = 0
    signal_segfault = 0
    failed_to_compile = 0
    failed_to_compile_cpp = 0

    for t, r in zip(tests, results):
        match r:
            case ResultCompilationFailure():
                failed_to_compile += 1
                if ".cpp" in t.source_paths[0]:
                    failed_to_compile_cpp += 1
            case ResultSignal(signal):
                failed_signal += 1
                if signal == 11:
                    signal_segfault += 1
            case ResultExit(3):
                correct_exit_code += 1
            case ResultExit(code):
                incorrect_exit_code += 1
                if code == 0:
                    zero_exit_code += 1
                else:
                    unexpected_exit_code += 1

    # fmt: off
    print("-----------------------------------------------------------------")
    print(f"Testing: {test_dir!r}")
    print(f"Total testcases: {len(tests)}")
    print(f"PASS: Number of cases with remediated exit code (exit code 3): {correct_exit_code}")
    print(f"\nFAIL: Number of cases with incorrect exit code (exit code != 3): {incorrect_exit_code}")
    print(f"      Number of cases exiting normally (exit code 0): {incorrect_exit_code}")
    print(f"      Number of cases exit with unexpected exit code: {unexpected_exit_code}")
    print(f"\nFAIL: Number of cases that terminate with signal: {failed_signal}")
    print(f"      Number of cases that terminate with segmentation faults: {signal_segfault}")
    print(f"\nFAIL: Number of cases failed to compile: {failed_to_compile}")
    print(f"      Number of cases failed to compile (Require C++ support): {failed_to_compile_cpp}")
    print(f"\nPercentage of CWE{test_dir.id} directory covered: {(correct_exit_code / len(tests)) * 100:.2f}%")
    print("-----------------------------------------------------------------")
    # fmt: on


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "CWEs", metavar="N", type=int, nargs="*", help="a CWE number to target"
    )
    args = parser.parse_args()

    cwe_ids: set[int] = set(args.CWEs)

    # Compile the io dependency needed for juliet test I/O
    io_obj = compile_io_c(Path("/tmp/io.o"))

    out_dir = Path.cwd() / "resolve_juliet_outputs"
    out_dir.mkdir()

    for test in CWETestDir.all_in_dir(juliet_testcases_dir):
        if test.id in cwe_ids:
            test_cwe(test, io_obj, out_dir)

if __name__ == "__main__":
    main()
