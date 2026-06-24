### `reach`
`reach` performs static reachability queries on `resolve` program metadata. It consumes the fact files extracted from binaries by `linker` and determines whether a path exists from the program entry point to a specified vulnerability. When a path is found, `reach` packages the results into a `.json` object and writes them either to a user-specified path or to `stdout` by default. 

A Python wrapper, `reach.py`, provides a convenient command-line interface to interact with `reach`. For more information about `reach`, see the [`reach`](https://github.com/riversideresearch/resolve/tree/main/reach) documentation.

