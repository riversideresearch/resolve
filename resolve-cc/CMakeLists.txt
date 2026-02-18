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

# Target: auto-format files
add_custom_target(format
    COMMAND clang-format -i ${SRC}
    COMMENT "Formatting source files with clang-format"
)

# Target: check formatting (no modifications)
add_custom_target(check-format
    COMMAND clang-format --dry-run --Werror ${SRC}
    COMMENT "Checking formatting with clang-format"
)

# Target: run clang-tidy
add_custom_target(lint
    COMMAND clang-tidy
            -p ${CMAKE_BINARY_DIR}
            ${SRC}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running clang-tidy"
)


# Combined check target
add_custom_target(check
    DEPENDS check-format lint
    COMMENT "Running all code quality checks"
)

# Build Targets
add_library(ResolveFacts STATIC IMPORTED GLOBAL)
set_target_properties(ResolveFacts PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../resolve-facts/build/libResolveFacts.a")
set_target_properties(ResolveFacts PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../resolve-facts/src/")

add_library(ResolveFactsPlugin SHARED src/ResolveFactsPlugin.cpp)
target_link_libraries(ResolveFactsPlugin PRIVATE ResolveFacts)

add_subdirectory(hooks)
