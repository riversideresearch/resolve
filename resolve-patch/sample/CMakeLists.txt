cmake_minimum_required(VERSION 3.10)
project(testrecomp)

add_executable(main main.c)
set(CMAKE_C_COMPILER "${CMAKE_SOURCE_DIR}/../../resolve-cc/bin/resolvecc")
set(CMAKE_CXX_COMPILER "${CMAKE_SOURCE_DIR}/../../resolve-cc/bin/resolvecc")

target_compile_options(main PRIVATE
    -fcve-assert
    "${CMAKE_SOURCE_DIR}/vulnerabilities.json"
    -fno-resolve
)