cmake_minimum_required(VERSION 3.20)
project(resolve-facts)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Release with symbols by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_subdirectory(libs/resolve_facts)
add_subdirectory(libs/resolve_facts_llvm)
