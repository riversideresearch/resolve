cmake_minimum_required(VERSION 3.20)
project(resolve)

include(${CMAKE_SOURCE_DIR}/cmake/AddCheckTargets.cmake)

# Add LLVM headers to include search paths
find_package(LLVM 18.1.3 CONFIG)
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20 STRING "")

# add_subdirectory(klee)
add_subdirectory(reach)
add_subdirectory(resolve-cc)
add_subdirectory(resolve-cveassert)
add_subdirectory(resolve-facts)
