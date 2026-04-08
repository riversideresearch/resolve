# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

cmake_minimum_required(VERSION 3.20)
project(resolve-facts)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(${CMAKE_SOURCE_DIR}/../cmake/AddCheckTargets.cmake)

    set(CMAKE_CXX_STANDARD 20 STRING "")
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(vendor/argparse)
add_subdirectory(vendor/json)

######################################################################
# RESOLVE FACTS

include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/resolve_facts/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/resolve_facts/*.hpp"
)

add_library(resolve_facts STATIC libs/resolve_facts/resolve_facts.cpp)
target_include_directories(resolve_facts PUBLIC 
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_link_libraries(resolve_facts PRIVATE glaze::glaze)

# Requires PIC because we want to embedd in shared objects
set_target_properties(resolve_facts PROPERTIES POSITION_INDEPENDENT_CODE ON)

# glaze features need cxx 23
target_compile_features(resolve_facts PUBLIC cxx_std_23)

if(COMMAND resolve_add_check_targets)
    resolve_add_check_targets(resolve_facts ${SRC})
endif()

install(TARGETS resolve_facts EXPORT resolve_facts_targets)
install(DIRECTORY include/resolve_facts DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

######################################################################
# RESOLVE FACTS LLVM

# Add LLVM headers to include search paths
find_package(LLVM CONFIG)

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/resolve_facts_llvm/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/resolve_facts_llvm/*.hpp"
)

# Build Targets
add_library(resolve_facts_llvm STATIC libs/resolve_facts_llvm/resolve_facts_llvm.cpp)
target_include_directories(resolve_facts_llvm SYSTEM PUBLIC ${LLVM_INCLUDE_DIRS})
target_link_libraries(resolve_facts_llvm PUBLIC resolve_facts)

target_include_directories(resolve_facts_llvm PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
set_target_properties(resolve_facts_llvm PROPERTIES POSITION_INDEPENDENT_CODE ON)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
    target_compile_options(resolve_facts_llvm PRIVATE -fno-rtti)
endif()

if(COMMAND resolve_add_check_targets)
    resolve_add_check_targets(resolve_facts_llvm ${SRC})
endif()

install(TARGETS resolve_facts_llvm EXPORT resolve_facts_targets)
install(DIRECTORY include/resolve_facts_llvm DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

######################################################################
# REACH

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/include/reach/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/reach/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/reach/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/reach/*.hpp"
)

# reach lib
add_library(libreach 
    libs/reach/distmap.cpp
    libs/reach/facts.cpp
    libs/reach/graph.cpp
    libs/reach/search.cpp
    libs/reach/util.cpp
)

set_target_properties(libreach PROPERTIES OUTPUT_NAME "reach")

target_include_directories(libreach PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_link_libraries(libreach PUBLIC resolve_facts json)

target_compile_features(libreach PUBLIC cxx_std_23)

# reach executable
add_executable(reach src/reach/main.cpp)

target_link_libraries(reach PRIVATE libreach json argparse)

if(COMMAND resolve_add_check_targets)
    resolve_add_check_targets(reach ${SRC})
endif()

install(TARGETS reach libreach EXPORT resolve_facts_targets)
install(DIRECTORY include/reach DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

######################################################################
# READ PROPS

add_executable(resolve_read_props src/read_props/main.cpp)
target_link_libraries(resolve_read_props PRIVATE resolve_facts glaze::glaze argparse)

target_compile_features(resolve_read_props PUBLIC cxx_std_23)

if(COMMAND resolve_add_check_targets)
    resolve_add_check_targets(resolve_read_props "${CMAKE_CURRENT_SOURCE_DIR}/src/read_props/main.cpp")
endif()

install(TARGETS resolve_read_props EXPORT resolve_facts_targets)

######################################################################
# Install Export Sets

install(EXPORT resolve_facts_targets 
    FILE ResolveFactsTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/ResolveFactsConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ResolveFactsConfig.cmake"
    #   "${CMAKE_CURRENT_BINARY_DIR}/ResolveFactsConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)
