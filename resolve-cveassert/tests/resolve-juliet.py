#!/usr/bin/env python3
import argparse, os, re, subprocess, pathlib, json, tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from subprocess import CalledProcessError

juliet_testsuite_root_dir = Path(__file__).parent

# Packages test name, number, with its result (pass, fail, exception)
# The exit_code field will be an enum that represents all the possible outcomes
# Outcomes:
# 

@dataclass
class Result:
    test_name: str
    test_number: str
    exit_code: int

    def __repr__(self) -> str:
        return f"Test name: {self.test_name}, Test number: {self.test_number}, Exit code: {self.exit_code}"


# Custom Error handling class when no affected functions can be found
class CouldNotFindFunctionSuffixInFile(Exception):
    """
    Custom exception when there are no
    functions in testcase source files
    that match the good and bad regex.
    """
    def __init__(self, lst):
        self.lst = lst
        super().__init__(
            "Cannot find a function in the source code that matches the good and bad regex."
        )

def compile_io_c(obj_file: Path):
    """
    Compile io.c into obj file 
    for linking
    """
    # TODO: Ask Jackson if we should do a static library
    # Compile io.c dependency to object file 
    juliet_testcase_support_headers = juliet_testsuite_root_dir / "testcasesupport"
    io_file = juliet_testcase_support_headers / "io.c"

    if obj_file.exists():
        return obj_file

    try:
        subprocess.run(
            [
                "clang",
                "-c",
                "-I", str(juliet_testcase_support_headers),
                str(io_file),
                "-o", str(obj_file)
            ],
            check=True
        )

    except CalledProcessError as compilation_error:
        print(f"[ERROR] Failed to compile io.o: {compilation_error}")

    return obj_file

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

def find_matching_file_identifier(source_path: Path):
    """
    Finds all source files in CWE directory that have
    matching identifiers. 

    Ex.
        CWE123_Write_What_Where_Condition_connect_socket_22a.c
        CWE123_Write_What_Where_Condition_connect_socket_22b.c

    """
    
    # Check if the path provided is a file or a directory
    # if source_path.is_dir():
    pass

def testCwe(testcase: tuple):
    print("\n>>> ENTERING testCwe() <<<")
    cwe_id, testcase_dir_path = testcase

    print(f"[DEBUGGING] Path: {testcase_dir_path}")

    grouped_tests = defaultdict(list)

    # Check to see if the source path is a directory or a file
    for file_count, source_path in enumerate(testcase_dir_path.iterdir()):
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
                print(f"[DEBUGGING]: ({file_count, source_code})")
    
        # Extract group key from stem
        stem = source_path.stem
        match = re.search(r"^(.*_\d+)", stem)

        if not match:
            continue

        group_key = match.group(1)
        grouped_tests[group_key].append(source_path)
        
    # Loop over all the testcases and store results in list
    results: list[Result] = []
    
    # Keeps track of total number of tests
    total_tests = 0

    # Counter keeps track of failed compilations 
    # that contain C source files
    failed_to_compile_c_build = 0
    
    # Counter keeps track of failed compilations
    # that contain CPP source files
    failed_to_compile_cpp_build = 0
    
    # Counter keeps track of the binaries executed that
    # exits with code 0 (in the bad case)
    # This will change based on the context 
    incorrect_exit_code_for_bad_testcase = 0

    # Counter keeps track of binaries executed that 
    # exit with codes that need manual inspection
    unexpected_exit_code = 0

    # Counter keeps track of the binaries executed that
    # signal a segmentation fault
    signal_segfault = 0
 
    # Compile the io dependency needed for juliet test I/O
    io_obj = compile_to_objfile(Path("/tmp/io.o"))

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
            use_cpp_compiler = any(f.suffix == ".cpp" for f in test_files)
            compiler = "clang++" if use_cpp_compiler else "clang"

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
                *[str(f) for f in test_files],
                str(io_obj),
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
            
            # Execute the compiled binary
            executed_binary = subprocess.run(
                [str(testcase_exe_path)],
                input="",
                capture_output=True,
                timeout=30,
                text=True
            )
        
        # Handle exception for failed compilation
        except CalledProcessError as compilation_error:
            print("[ERROR] Compilation failed: ", compilation_error)
            # Determine the reason for the error
            # If the cpp compiler is used when the error occurs then report it 
            # Non-zero exit code signifies error in compilation
            if use_cpp_compiler and compilation_error.returncode:
                # Increment the counter
                print(f"[FAILURE] Failed to compile CPP source code for {testcase_exe_path}.")
                failed_to_compile_cpp_build += 1


            elif compilation_error.returncode:
                print(f"[FAILURE] Failed to compile C source code for {testcase_exe_path}.")
                failed_to_compile_c_build += 1

            # Record the result
            results.append(Result(test_name, test_number, compilation_error.returncode))
            
            # Once the program enters a failed build state, move onto the next test 
            continue

        # Handle runtime exception
        except Exception as execution_error:
            print("[ERROR] Execution failed: ", execution_error)
            if execution_error.returncode == 0:
                print(f"[FAILURE] Failed to remediate program. Remediation did not detect vulnerability pattern. Exiting program with incorrect exit code.")
                incorrect_exit_code_for_bad_testcase += 1
            
            # NOTE: The negative value indicates that the program has been signaled 
            elif execution_error.returncode == -11: # SIGSEGV
                print(f"[FAILURE] Segmentation fault occurred. Remediation failed.")
                signal_segfault += 1

            # NOTE: Might need to add better handling of exit codes and signals.
            else:
                print(f"[FAILURE] Failed to remediate program. Manual inspection of signal or error code required.")
                unexpected_exit_code += 1
            
            results.append(Result(test_name, test_number, execution_error.returncode))
            continue

    print("-----------------------------------------------------------------")
    print(f"Total testcases: {total_tests}\n")
    print(f"Number of cases exit with remediated code (exit code 3): {correct_exit_code}\n")
    print(f"Number of cases exit with incorrect code (exit with code 0): {incorrect_exit_code}\n")
    print(f"Number of cases exit with unexpected exit code: {unexpected_exit_code}")
    print(f"Number of cases that terminate with segmentation faults: {signal_segfault}\n")
    print(f"Number of cases failed to compile: {failed_to_compile}\n")
    print(f"Number of cases failed to compile (Require C++ support): {failed_to_compile_cpp_build}\n")
    print(f"Percentage of CWE{cwe_id} directory covered: { (correct_exit_code / total_tests) * 100:.2f}%")
    print("-----------------------------------------------------------------")

    
def testAllCwes(cwe_ids: set):
    """
    Matches cwe id of the directory with user specified.
    """
    
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

    for cwe_dir_path in matching_cwedirs:
        testCwe(cwe_dir_path)

def getCveDescription(cwe_id: int, test_files: list[Path]):
    """ 
    Creates a CVE description by locating affected functions 
    within files per a particular test 
    """

    affected_functions = findBad(test_files) + findGood(test_files)
    
    if not affected_functions:
        print("No affected function found!") # replace with error handler
        raise CouldNotFindFunctionSuffixInFile(affected_functions)

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
