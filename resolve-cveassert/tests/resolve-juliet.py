#!/usr/bin/env python3
import argparse, os, re, subprocess, pathlib, json
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
import tempfile

juliet_testsuite_root_dir = Path(__file__).parent

# Packages test name, number, with its result (pass, fail, exception)
@dataclass
class Result:
    test_name: str
    test_number: str
    exit_code: int

    def __repr__(self) -> str:
        return f"Test name: {self.test_name}, Test number: {self.test_number}, Exit code: {self.exit_code}"



def find_matching_file_contents(source_files: list[Path], pattern: re.Pattern) -> list[tuple]:
    """ 
    Finds the first match group of `pattern` in each file in `source_files`
    Returns a list of pairs of the form (<matched_file>, match.group(1))
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
                    # get the full function name
                    function_name = match.group(1)
                    # add the path the list
                    matched_files.append((path, function_name))
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

    bad_files = find_matching_file_contents(source_files, bad_pattern)

    return bad_files

def findGood(source_files: list[Path]) -> list[tuple]:
    """
    Given a list of source files, return the files
    that contain a CWE good function defintion.
    """ 

    cwe_good_pattern = re.compile(
    r"^\s*(?:static\s+)?(?:void|int)\s+(\w+_good)\s*\(",
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

    #TODO: Add regular expression for good?

    matching_cwe_pattern_files = find_matching_file_contents(source_files, cwe_good_pattern)
    matching_g_b_pattern_files = find_matching_file_contents(source_files, good_g_b_flow_pattern)
    
    # Return both lists as a combined list
    return matching_cwe_pattern_files + matching_g_b_pattern_files 
 
def testCwe(testcase: tuple):
    print("\n>>> ENTERING testCwe()")
    cwe_id, testcase_dir_path = testcase

    print(f"[DEBUGGING] Path: {testcase_dir_path}")

    grouped_tests = defaultdict(list)
    file_counter = 0


    # Check to see if the source path is a directory or a file
    for source_path in testcase_dir_path.iterdir():
        if source_path.is_dir():
            for source_code in source_path.iterdir():
                # Ignoring _listen_socket tests because they hang
                # forever waiting for socket connection
                # We assume they are redundant to other easier
                # to integrate test for our purposes
                if "_listen_socket_" in source_code.name:
                    continue

                stem = source_code.stem
                match = re.search(r"^(.*_\d+)", stem)
                
                if not match:
                    continue

                group_key = match.group(1)
                grouped_tests[group_key].append(source_code) 

        # if not source_path.is_file():
        #     continue
    
        # Extract group key from stem
        stem = source_path.stem
        match = re.search(r"^(.*_\d+)", stem)

        if not match:
            continue

        group_key = match.group(1)
        grouped_tests[group_key].append(source_path)
        
        # [DEBUGGING]
        file_counter += 1

    # print("             ==== [DEBUGGING] ====")
    # for key, files in sorted(grouped_tests.items()):
    #     print(f"\nTest group: {key}")
    #     for f in sorted(files):
    #         print("     ", f.name)
    print(f"\n[DEBUGGING] Number of relevant files: {file_counter}\n")
    # print("             ==== [DEBUGGING] ====")

    # for key, files in sorted(grouped_tests.items()):
    #     print(f"\nChecking groups: {key}")
    #     bad_files = findBad(files)

    #     if bad_files:
    #         print(" BAD cases found: ")
    #         for bf in bad_files:
    #             print("     ", bf[0].name)
    #     else:
    #         print(" No BAD cases found")

    # for key, files in sorted(grouped_tests.items()):
    #     print(f"\nChecking groups: {key}")
    #     good_files = findGood(files)

    #     if good_files:
    #         print(" GOOD cases found: ")
    #         for gf in good_files:
    #             print("     ", gf.name)
    #     else:
    #         print(" No GOOD cases found")
    
    # DEBUG to see how the JSON would look
    # for key, test_files in sorted(grouped_tests.items()):
    #     cve_descriptions = getCveDescription(cwe_id, test_files)
    #     print(f"\nJSON output for group {key}:\n{cve_descriptions}")

    # Loop over all the testcases and store results in list
    results: list[Result] = []
    total_tests = 0
    failed_to_compile = 0
    failed_to_compile_cpp_build = 0
    correct_exit_code = 0
    incorrect_exit_code = 0
    signal_segfault = 0
    
    for test_key, test_files in sorted(grouped_tests.items()):
        
        total_tests+= 1

        # Binary path to compiled testcase executable
        testcase_exe_path = Path("/tmp") / f"{cwe_id}_{test_files[0].stem}"
        # Create the JSON-formatted CVE description
        cve_descriptions = getCveDescription(cwe_id, test_files)

        try:

            # Set the environment variable
            env_var = os.environ.copy()
            env_var["RESOLVE_LABEL_CVE"] = cve_descriptions

            # Determine which compiler to use based on extensions
            use_cpp = any(f.suffix == ".cpp" for f in test_files)
            compiler = "clang++" if use_cpp else "clang"

            # Support files for compilation
            testsupport_dir = juliet_testsuite_root_dir / "testcasesupport"
            io_file = testsupport_dir / "io.c"

            # NOTE: Do NOT compile a binary and its source in the same directory
            compile_cmd = [
                compiler,
                "-fpass-plugin=/opt/resolve/lib/libCVEAssert.so",
                "-L/opt/resolve/lib",
                "-lresolve",
                "-Wl,-rpath=/opt/resolve/lib",
                "-DOMITGOOD",
                "-DINCLUDEMAIN",
                "-I", str(testsupport_dir),
                str(io_file),
                *[str(f) for f in test_files],
                "-o", str(testcase_exe_path)
            ]

            # Compile source files with CVE description
            process = subprocess.run(
                compile_cmd,
                env=env_var,
                capture_output=True,
                check=True,         # If the compilation fails then a CalledProcessError exception is raised
                text=True
            )

            # Check if return code is 0 (clean compilation)
            if process.returncode != 0:
                print(f"\nCompilation failed for: {testcase_exe_path}")
                print(process.stderr)
                failed_to_compile += 1
                continue

            
            # Execute the compiled binary
            executed_binary = subprocess.run(
                [str(testcase_exe_path)],
                input="",
                capture_output=True,
                timeout=30,
                text=True
            )

            # Check if binary exits with remediation code
            if executed_binary.returncode == 3:
                correct_exit_code += 1
            
            # Check if the binary terminates with signal SIGSEV
            elif executed_binary.returncode == -11:
                signal_segfault += 1

            # Check if the binary retcode is 0
            elif executed_binary.returncode == 0:
                incorrect_exit_code += 1 
        
        except Exception as e:
            print("Compilation failed: ", e)
            if use_cpp:
                failed_to_compile_cpp_build += 1
            else:
                failed_to_compile += 1

        match = re.search(r"(.*)_(\d+)$", test_key)
        test_name = match.group(1)
        test_number = match.group(2)

        results.append(Result(test_name, test_number, executed_binary.returncode))

    print("-----------------------------------------------------------------")
    print(f"Total testcases: {total_tests}\n")
    print(f"Number of cases exit with remediated code (exit code 3): {correct_exit_code}\n")
    print(f"Number of cases exit with incorrect code (exit with code 0): {incorrect_exit_code}\n")
    print(f"Number of cases that terminate with segmentation faults: {signal_segfault}\n")
    print(f"Number of cases failed to compile: {failed_to_compile}\n")
    print(f"Number of cases failed to compile (Require C++ support): {failed_to_compile_cpp_build}\n")
    print(f"Percentage of CWE{cwe_id} directory covered: { (correct_exit_code / total_tests) * 100:.2f}%")
    print("-----------------------------------------------------------------")

    # for result in results:
    #     print(repr(result))
    
def testAllCwes(cwe_ids: set):
    testcases = juliet_testsuite_root_dir / "testcases"

    # DEBUGGING: print the ids
    print("[DEBUGGING] CWE-ids:", cwe_ids)

    # Loop over every relevant file in testcases/ that has a matching ID
    matching_cwedirs = []

    for cwe_dir in testcases.iterdir():
        match = re.search(r"^CWE(\d+)_*", cwe_dir.name)
        if match:
            
            parsed_cwe_id = int(match.group(1))

            if parsed_cwe_id in cwe_ids:
                print("DIR FOUND:", repr(cwe_dir.name))
                matching_cwedirs.append(tuple([parsed_cwe_id, cwe_dir]))

    # Stores the paths of the matching cwe directories
    print(f"[DEBUGGING] matching cwe-dirs: {matching_cwedirs}")

    for cwe_path in matching_cwedirs:
        testCwe(cwe_path)

def getCveDescription(cwe_id: int, test_files: list[Path]):
    """ 
    Creates a CVE description by locating affected functions 
    within files per a particular test 
    """

    affected_functions = findBad(test_files) + findGood(test_files)
    
    if not affected_functions:
        print("No affected function found!") # replace with error handler
        # raise CouldNotFindBadFunction 

    # Build JSON
    vulnerabilities = [
        {
            "cwe-id": str(cwe_id),
            "affected-function": func,
            "affected-file": str(file),
            "remediation-strategy": "exit"
        }
        for file, func in affected_functions
    ]

    json_obj = {"vulnerabilities" : vulnerabilities }

    json_path = Path("/tmp") / f"{test_files[0].stem}.json" 

    with json_path.open("w") as f:
        json.dump(json_obj, f, indent=4)

    return json_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("CWEs", metavar="N", type=int, nargs="*", help="a CWE number to target")
    args = parser.parse_args()
    args.CWEs = set(args.CWEs)
    testAllCwes(args.CWEs)
