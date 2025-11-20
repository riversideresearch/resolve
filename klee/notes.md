# Misc notes

At `lib/Core/Executor.cpp:698`:
> we don't need to allocate a memory object since reading/writing via a function pointer is unsupported anyway.

What does this mean? Just that it needs to concretize reads and writes
to function pointers? We could potentially change it to fan out to all
possible functions (address-taken, and external linkage if dynamic
linking), OR use runtime data to underapproximate instead (since DSE
with KLEE is inherently an underapproximating thing).

# KLEE options

## Disable checks
```
--check-div-zero  - Inject checks for division-by-zero (default=true)
--check-overshift - Inject checks for overshift (default=true)
```

## Things to experiment with
```
-cex-cache-superset                                    - Try substituting SAT superset counterexample before asking the SMT solver (default=false)
--cex-cache-try-all                                     - Try substituting all counterexamples before asking the SMT solver (default=false)
--rewrite-equalities                                    - Rewrite existing constraints when an equality with a constant is added (default=true)
--simplify-sym-indices                                  - Simplify symbolic accesses using equalities from other constraints (default=false)
--compress-exec-tree                                    - Remove intermediate nodes in the execution tree whenever possible (default=false)
--use-construct-hash-z3                                 - Use hash-consing during Z3 query construction (default=true)
--use-visitor-hash                                      - Use hash-consing during expression visitation (default=true)

```

## Might be useful
```
--smtlib-human-readable                                 - Enables generated SMT-LIBv2 files to be human readable (default=false)
--link-llvm-lib=<bitcode library file>                  - Link the given bitcode library before execution, e.g. .bca, .bc, .a. Can be used multiple times.
--rng-initial-seed=<ulong>                              - seed value for random number generator (default=5489)
--single-object-resolution                              - Try to resolve memory reads/writes to single objects when offsets are symbolic (default=false)
-use-incomplete-merge                                  - Heuristic-based path merging (default=false)
--use-merge                                             - Enable support for path merging via klee_open_merge and klee_close_merge (default=false)
--entry-point=<string>                                  - Function in which to start execution (default=main)
--env-file=<string>                                     - Parse environment from the given file (in "env" format)
--optimize                                              - Optimize the code before execution (default=false).
--warn-all-external-symbols                             - Issue a warning on startup for all external symbols (default=false).
--silent-klee-assume                                    - Silently terminate paths with an infeasible condition given to klee_assume rather than emitting an error (default=false)
--readable-posix-inputs                                 - Prefer creation of POSIX inputs (command-line arguments, files, etc.) with human readable bytes. Note: option is expensive when creating lots of tests (default=false)
```

## Exiting on specific errors
```
--exit-on-error-type=<value>                            - Stop execution after reaching a specified condition (default=false)
    =Abort                                                -   The program reached abort or klee_abort
    =Assert                                               -   An assertion was hit
    =BadVectorAccess                                      -   Vector accessed out of bounds
    =Execution                                            -   Trying to execute an unexpected instruction
    =External                                             -   External objects referenced
    =Free                                                 -   Freeing invalid memory
    =Model                                                -   Memory model limit hit
    =Overflow                                             -   An overflow occurred
    =Ptr                                                  -   Pointer error
    =ReadOnly                                             -   Write to read-only memory
    =ReportError                                          -   klee_report_error called
    =InvalidBuiltin                                       -   Passing invalid value to compiler builtin
    =ImplicitTruncation                                   -   Implicit conversion from integer of larger bit width to smaller bit width that results in data loss
    =ImplicitConversion                                   -   Implicit conversion between integer types that changes the sign of the value
    =UnreachableCall                                      -   Control flow reached an unreachable program point
    =MissingReturn                                        -   Reaching the end of a value-returning function without returning a value
    =InvalidLoad                                          -   Load of a value which is not in the range of representable values for that type
    =NullableAttribute                                    -   Violation of nullable attribute detected
    =User                                                 -   Wrong klee_* function invocation
```

## Might hijack
```
--replay-path=<path file>                               - Specify a path file to replay
--seed-file=<string>                                    - .ktest file to be used as seed
```

Might be able to use these to implement our own path seeding, but
might be better to just do it separately.

## Search options
```
--search=<value>                                        - Specify the search heuristic (default=random-path interleaved with nurs:covnew)
    =dfs                                                  -   use Depth First Search (DFS)
    =bfs                                                  -   use Breadth First Search (BFS), where scheduling decisions are taken at the level of (2-way) forks
    =random-state                                         -   randomly select a state to explore
    =random-path                                          -   use Random Path Selection (see OSDI'08 paper)
    =nurs:covnew                                          -   use Non Uniform Random Search (NURS) with Coverage-New
    =nurs:md2u                                            -   use NURS with Min-Dist-to-Uncovered
    =nurs:depth                                           -   use NURS with depth
    =nurs:rp                                              -   use NURS with 1/2^depth
    =nurs:icnt                                            -   use NURS with Instr-Count
    =nurs:cpicnt                                          -   use NURS with CallPath-Instr-Count
    =nurs:qc                                              -   use NURS with Query-Cost
--use-batching-search                                   - Use batching searcher (keep running selected state for N instructions/time, see --batch-instructions and --batch-time) (default=false)
--batch-instructions=<uint>                             - Number of instructions to batch when using --use-batching-search.  Set to 0 to disable (default=10000)
--batch-time=<string>                                   - Amount of time to batch when using --use-batching-search.  Set to 0s to disable (default=5s)
```

# Misc notes

Arguments to external function calls need to be concretized. Do we
ever need to call external functions? Or do we have sources for
everything?


# Running KLEE on json_parser

Requires our changes to `klee-uclibc` for `sscanf`.

```bash
cd ~/source/resolve/exemplars/exemplar-2/json_parser
git switch klee-json && git pull
LLVM_COMPILER=clang LLVM_CC_NAME=clang-16 make CC=wllvm LD=wllvm
find build -executable -type f | xargs -I '{}' extract-bc -l $HOME/klee_deps/llvm-160-build_O_ND_NA/bin/llvm-link '{}'
~/source/klee/build/bin/klee --only-output-states-covering-new  --libc=uclibc --posix-runtime build/parser.bc --sym-arg 30
```
