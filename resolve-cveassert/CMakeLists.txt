cmake_minimum_required(VERSION 3.20)
project(resolve-cveassert)

find_package(LLVM 18.1.3 CONFIG)

include(../cmake/AddCheckTargets.cmake)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# Release with symbols by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_CXX_STANDARD 20 STRING "")

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.hpp"
)

# Build Targets
add_library(CVEAssert SHARED 
  src/CVEAssert.cpp
  src/bounds_check.cpp
  src/null_ptr.cpp
  src/arith_san.cpp
  src/helpers.cpp
  src/undesirableop.cpp
)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(CVEAssert PRIVATE -fno-rtti)
endif()

resolve_add_check_targets(CVEAssert ${SRC})

# Test Targets
add_custom_target(test-CVEAssert 
    lit -v ${CMAKE_CURRENT_SOURCE_DIR}/tests/
    DEPENDS CVEAssert
    COMMENT "Running regression tests for CVEAssert"
)
