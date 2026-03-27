#!/usr/bin/env python3
from abc import ABC
from itertools import groupby
import shutil
from signal import Signals
import argparse
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
import sys

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
    cwe: int
    dir: Path
    name: str

    def __str__(self):
        return f"{self.cwe}: {self.name}"

    @classmethod
    def from_dir(cls, dir: Path) -> "CWETestDir | None":
        """Create a `CWETestDir` from a path of the form CWEXXX_*"""
        match = re.search(r"^CWE(\d+)_(.*)", dir.name)
        if match is None:
            return None
        cwe, name = match.groups()
        return cls(cwe=int(cwe), name=name, dir=dir)

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

    def collect_tests(self, test_limit: int) -> "list[CWETest]":
        """Collect tests in `self`

        Each test may contain multiple sources.
        """
        # Map test name to all of its source files
        test_src_files: defaultdict[tuple[int, str], list[Path]] = defaultdict(list)

        # Group source files according to name (words followed by an index)
        for source_path in self.iterdir():
            # Extract group key from stem
            stem = source_path.stem
            match = re.search(r"^.*_(\d+)", stem)

            if not match:
                print(
                    f"WARN: No test matching file {source_path.name}", file=sys.stderr
                )
                continue

            testcase_name = match.group(0)
            testcase_idx = int(match.group(1))
            if (
                len(test_src_files) == test_limit
                and (testcase_idx, testcase_name) not in test_src_files
            ):
                print(
                    f"WARN: Skipping remaining tests in {self.name} after {test_limit} tests",
                    file=sys.stderr,
                )
                break

            test_src_files[(testcase_idx, testcase_name)].append(source_path)

        tests = [
            CWETest(self.cwe, idx, name, source_paths)
            for (idx, name), source_paths in test_src_files.items()
        ]
        return sorted(tests, key=lambda t: t.idx)


@dataclass
class CWETest:
    cwe: int
    idx: int
    name: str
    source_paths: list[Path]

    def __str__(self):
        return self.name

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
                "cwe-id": str(self.cwe),
                "affected-function": func,
                "affected-file": str(file),
                "remediation-strategy": "exit",
            }
            for func, files in affected_functions
            for file in files
        ]

        return {"vulnerabilities": vulnerabilities}


@dataclass
class Result(ABC):
    """The outcome of a single test"""

    exit_code = None
    exit_signal = None
    timeout = False
    skip_reason = None
    failed_compilation_process = None

    def get_signal_name(self):
        if self.exit_signal is not None:
            return Signals(self.exit_signal).name or f"signal {self.exit_signal}"
        else:
            return None

@dataclass
class ResultExit(Result):
    exit_code: int

    def __str__(self) -> str:
        return f"exit {self.exit_code}"

@dataclass
class ResultSignal(Result):
    exit_signal: int

    def __str__(self) -> str:
        return f"exit {self.get_signal_name()}"

@dataclass
class ResultTimeout(Result):
    timeout = True

    def __str__(self) -> str:
        return "timeout"


@dataclass
class ResultSkipped(Result):
    skip_reason: str

    def __str__(self) -> str:
        return f"skipped: {self.skip_reason}"

@dataclass
class ResultCompilationFailure(Result):
    failed_compilation_process: CompletedProcess[str]

    def __str__(self) -> str:
        return "failed_to_compile"


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


def test_cwe(test_dir: CWETestDir, io_obj: Path, out_dir: Path, test_limit: int):
    tests = test_dir.collect_tests(test_limit)
    results = [(test, do_test(test, io_obj, out_dir)) for test in tests]

    pass_results = [(t, r) for t, r in results if r.exit_code == 3]
    fail_results = [(t, r) for t, r in results if r.exit_code != 3]

    def summarize_results(results: list[tuple[CWETest, Result]]):
        SUMMARY_LEN = 10

        def key(results: tuple[CWETest, Result]):
            return str(results[1])

        grouped = groupby(sorted(results, key=key), key=key)
        for g, gr in grouped:
            group_results = list(gr)
            print(f"{g} ({len(group_results)} tests...)")
            print("\n".join(f"  {t.name}" for t, _ in group_results[:SUMMARY_LEN]))
            if len(group_results) > SUMMARY_LEN:
                print("  ...")

    def show_result(label: str, results: list[tuple[CWETest, Result]]):
        print(f"{label}: {len(results)}")
        if len(results):
            summarize_results(results)

    pass_count = len(pass_results)
    total_tests = len(tests)
    success_percent = (pass_count / total_tests) * 100

    print("-----------------------------------------------------------------")
    print(f"Testing: {test_dir}")
    print(f"Total testcases: {len(tests)}")
    show_result("PASS", pass_results)
    show_result("FAIL", fail_results)
    print("-----------------------------------------------------------------")
    print(f"Percentage of CWE{test_dir.cwe} directory covered: {success_percent:.2f}%")
    print(flush=True)

    return pass_count, total_tests


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
        "--limit",
        type=int,
        default=50,
        help="Limit the number of tests processed per CWE",
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
    test_limit = args.limit

    if not juliet_testcases_dir.exists():
        tar_file = juliet_testcases_dir.with_suffix(".tar.xz")
        subprocess.run(["tar", "-xf", str(tar_file)], check=True)

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

    test_dirs = [
        t for t in CWETestDir.all_in_dir(juliet_testcases_dir) if t.cwe in cwe_ids
    ]
    for test_dir in test_dirs:
        n = sum(1 for _ in test_dir.iterdir())
        print(f"Testing: {test_dir} ({n} tests...)")
    print(flush=True)

    total_pass_count = 0
    total_tests = 0
    for test_dir in test_dirs:
        pass_count, tests = test_cwe(test_dir, io_obj, out_dir, test_limit)

        total_pass_count += pass_count
        total_tests += tests

    success_percent = (total_pass_count / total_tests) * 100

    print("-----------------------------------------------------------------")
    print(f"Total pass: {total_pass_count}")
    print(f"Total testcases: {total_tests}")
    print(f"Percentage covered: {success_percent:.2f}%")

if __name__ == "__main__":
    main()
