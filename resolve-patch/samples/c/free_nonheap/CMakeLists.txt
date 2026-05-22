cmake_minimum_required(VERSION 3.10)
project(resolve_sample_c_free_nonheap C)

set(CMAKE_C_COMPILER "${CMAKE_SOURCE_DIR}/../../../../resolve-cc/bin/resolvecc")

add_executable(main main.c)
target_compile_options(main PRIVATE
    -fcve-assert "${CMAKE_SOURCE_DIR}/vulnerabilities.json"
    -fno-resolve
)
