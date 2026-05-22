cmake_minimum_required(VERSION 3.10)
project(resolve_sample_cpp_free_nonheap CXX)

set(CMAKE_CXX_COMPILER "${CMAKE_SOURCE_DIR}/../../../../resolve-cc/bin/resolvecxx")

add_executable(main main.cpp)
target_compile_options(main PRIVATE
    -fcve-assert "${CMAKE_SOURCE_DIR}/vulnerabilities.json"
    -fno-resolve
)
