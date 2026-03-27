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
from subprocess import CompletedProcess, TimeoutExpired

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

    @staticmethod
    def match_function_name_in_file(path: Path, name_pattern: str) -> str | None:
        """Given a regex in `name_pattern`, tries to find a matching function in `file` using a naive regex"""
        pattern = re.compile(
            r"^\s*(?:static\s+)?(?:void|int)\s+(" + name_pattern + r")\s*\("
        )

        with path.open("r") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    return match.group(1)

    def find_matching_function_names(self, name_pattern: str):
        """Given a regex in `name_pattern`, tries to find a matching function in each `file` using a naive regex"""

        matches: defaultdict[str, list[Path]] = defaultdict(list)

        for path in self.source_paths:
            if match := self.match_function_name_in_file(path, name_pattern):
                matches[match].append(path)

        return matches

    def get_cve_description(self):
        """
        Creates a CVE description by locating affected functions
        within files per a particular test
        """

        bad_functions = self.find_matching_function_names(r"\w+_bad")
        good_functions = self.find_matching_function_names(r"good(?:G\d+B\d*|B\d+G\d*)")
        # only try _good if there is not a more specific goodGXBX version
        # good usually delegates to one of those if that is the case
        if len(good_functions) == 0:
            good_functions = self.find_matching_function_names(r"\w+_?good")

        affected_functions = [*bad_functions.items(), *good_functions.items()]

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
            for func, files in affected_functions
            for file in files
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
class ResultTimeout(Result):
    pass

@dataclass
class ResultSkipped(Result):
    skip_reason: str



@dataclass
class ResultCompilationFailure(Result):
    called_process: CompletedProcess[str]


def do_test(test: CWETest, io_obj: Path, out_dir: Path) -> Result:
    if "socket" in test.name:
        return ResultSkipped("socket")

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

    compile_process = subprocess.run(
        compile_cmd, env=env_var, capture_output=True, text=True
    )
    if compile_process.returncode != 0:
        return ResultCompilationFailure(compile_process)

    try:
        executed_binary = subprocess.run(
            [str(testcase_exe_path)], 
            input="", # don't share stdin
            capture_output=True, 
            timeout=30, # detect hangs (i.e., networking tests)
            cwd=out_dir, # Run in out dir, attempt to contain log files
        )
    except TimeoutExpired:
        return ResultTimeout()

    match executed_binary.returncode:
        case i if i >= 0:
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
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Replace the existing output directory if it exists",
    )
    parser.add_argument(
        "--out_dir",
        type=Path,
        default=Path.cwd() / "resolve_juliet_outputs",
        help="Directory to write intermediate and output files to",
    )
    args = parser.parse_args()

    DEFAULT_CWEs = (
        121,  # STACK_BASED_BUF_OVERFLOW
        122,  # HEAP_BASED_BUF_OVERFLOW
        123,  # WRITE_WHAT_WHERE
        787,  # OOB_WRITE
        125,  # OOB_READ
        131,  # INCORRECT_BUF_SIZE
        369,  # DIVIDE_BY_ZERO
        190,  # INT_OVERFLOW
        476,  # NULL_PTR_DEREF
        590,  # STACK_FREE
    )

    cwe_ids: set[int] = set(args.CWEs if args.CWEs else DEFAULT_CWEs)
    out_dir: Path = args.out_dir
    overwrite_dir = args.force

    try:
        out_dir.mkdir()
    except FileExistsError:
        if overwrite_dir:
            shutil.rmtree(out_dir)
            out_dir.mkdir()
        else:
            parser.exit(
                message=f"ERROR: Output dir {out_dir} exists...\nRename it, or try again with -f/--force\n"
            )

    # Compile the io dependency needed for juliet test I/O
    io_obj = compile_io_c(out_dir)

    for test in CWETestDir.all_in_dir(juliet_testcases_dir):
        if test.id in cwe_ids:
            test_cwe(test, io_obj, out_dir)

if __name__ == "__main__":
    main()
