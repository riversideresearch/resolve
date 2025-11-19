cmake_minimum_required(VERSION 3.20)
project(resolve-llvm-plugin)

find_package(LLVM CONFIG)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
#include_directories(SYSTEM /home/srosefield/projects/rust/build/x86_64-unknown-linux-gnu/llvm/include/llvm)

#link_libraries(/home/srosefield/projects/rust/build/host/stage0/lib/libLLVM-21-rust-1.92.0-beta.so)

# Debug by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_STANDARD 17 STRING "")

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# Clang format
find_program(CLANG_FORMAT_EXECUTABLE clang-format)
if(NOT CLANG_FORMAT_EXECUTABLE)
    message(FATAL_ERROR "clang-format not found. Please install it or add it to your PATH.")
endif()

file(GLOB_RECURSE PROJECT_SOURCE_FILES
    "${CMAKE_SOURCE_DIR}/*.cpp"
    "${CMAKE_SOURCE_DIR}/*.hpp"
    "${CMAKE_SOURCE_DIR}/*.c"
    "${CMAKE_SOURCE_DIR}/*.h"
)

add_custom_target(clangformat
    COMMAND ${CLANG_FORMAT_EXECUTABLE} -i ${PROJECT_SOURCE_FILES}
    COMMENT "Formatting source files with clang-format..."
)

add_library(EnhancedFacts SHARED EnhancedFacts.cpp)
add_library(CVEAssert SHARED 
  CVEAssert/CVEAssert.cpp
  CVEAssert/bounds_check.cpp
  CVEAssert/null_ptr.cpp
  CVEAssert/arith_san.cpp
  CVEAssert/helpers.cpp
)
add_library(AnnotateFunctions SHARED AnnotateFunctions.cpp)
add_library(ObjHook SHARED ObjHook.cpp)
add_library(DlsymHook SHARED DlsymHook.cpp)
