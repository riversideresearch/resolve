cmake_minimum_required(VERSION 3.15)
project(remediation-example C)

set(CMAKE_C_COMPILER "resolvecc") 
set(CMAKE_CXX_COMPILER "resolvecc")

add_executable(remediation-example src/main.c)

target_compile_options(remediation-example PRIVATE -fcve-assert ../vulnerabilities.json)