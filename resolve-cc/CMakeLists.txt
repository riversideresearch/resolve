cmake_minimum_required(VERSION 3.20)
project(resolve-llvm-plugin)

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

# clang-tidy needs compile commands to work correctly
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()


# Format and lint checks
# Collect source files
file(GLOB_RECURSE SRC
    "${CMAKE_SOURCE_DIR}/hooks/*.cpp"
    "${CMAKE_SOURCE_DIR}/hooks/*.hpp"
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.hpp"
)

resolve_add_check_targets(ResolveFactsPlugin ${SRC})

# Build Targets
add_subdirectory(hooks)

add_library(ResolveFactsPlugin SHARED src/ResolveFactsPluginPass.cpp)
target_link_libraries(ResolveFactsPlugin PRIVATE resolve_facts_llvm)
