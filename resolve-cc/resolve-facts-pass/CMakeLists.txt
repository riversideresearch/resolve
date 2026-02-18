cmake_minimum_required(VERSION 3.20)
project(resolve-llvm-plugin)

find_package(LLVM 18.1.3 CONFIG)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# Release with symbols by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_CXX_STANDARD 20 STRING "")

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

add_library(ResolveFacts STATIC IMPORTED GLOBAL)
set_target_properties(ResolveFacts PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../../resolve-facts/build/libResolveFacts.a")
set_target_properties(ResolveFacts PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../../resolve-facts/src/")

add_library(ResolveFactsPlugin SHARED src/ResolveFactsPlugin.cpp)
target_link_libraries(ResolveFactsPlugin PRIVATE ResolveFacts)
