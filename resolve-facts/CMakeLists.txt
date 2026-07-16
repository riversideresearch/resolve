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

######################################################################
# RUST FACTS ABI

set(FACTS_RS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rs")
set(FACTS_RS_TARGET_DIR "${FACTS_RS_DIR}/target/release")
set(FACTS_RS_STATICLIB "${FACTS_RS_TARGET_DIR}/libfacts_rs.a")
set(FACTS_RS_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(FACTS_RS_HEADER "${FACTS_RS_GENERATED_DIR}/facts_rs.hpp")
file(MAKE_DIRECTORY "${FACTS_RS_GENERATED_DIR}")

find_program(CARGO_EXECUTABLE cargo REQUIRED)
find_program(CBINDGEN_EXECUTABLE cbindgen HINTS "$ENV{HOME}/.cargo/bin" REQUIRED)

file(GLOB FACTS_RS_SOURCES CONFIGURE_DEPENDS "${FACTS_RS_DIR}/src/*.rs")
add_custom_command(
  OUTPUT "${FACTS_RS_STATICLIB}" "${FACTS_RS_HEADER}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${FACTS_RS_GENERATED_DIR}"
  COMMAND "${CARGO_EXECUTABLE}" build --manifest-path "${FACTS_RS_DIR}/Cargo.toml" --release
  COMMAND "${CBINDGEN_EXECUTABLE}" --config "${FACTS_RS_DIR}/cbindgen.toml"
          --crate facts-rs --output "${FACTS_RS_HEADER}" "${FACTS_RS_DIR}"
  DEPENDS ${FACTS_RS_SOURCES} "${FACTS_RS_DIR}/Cargo.toml" "${FACTS_RS_DIR}/Cargo.lock"
          "${FACTS_RS_DIR}/cbindgen.toml"
  WORKING_DIRECTORY "${FACTS_RS_DIR}"
  COMMENT "Building facts-rs and generating its C++ ABI header"
  VERBATIM
)
add_custom_target(facts_rs_build DEPENDS "${FACTS_RS_STATICLIB}" "${FACTS_RS_HEADER}")

add_library(facts_rs STATIC IMPORTED GLOBAL)
set_target_properties(facts_rs PROPERTIES
  IMPORTED_LOCATION "${FACTS_RS_STATICLIB}"
  INTERFACE_INCLUDE_DIRECTORIES "${FACTS_RS_GENERATED_DIR}"
)
add_dependencies(facts_rs facts_rs_build)

add_subdirectory(vendor/argparse)
add_subdirectory(vendor/json)

######################################################################
# RESOLVE FACTS

include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG 94222ecb0de39c5e6c83e708f0825ecb6aeae11f
  GIT_SHALLOW FALSE
)

set(glaze_INSTALL ON CACHE BOOL "Generate installation rules for glaze" FORCE)
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
find_package(Threads REQUIRED)
target_link_libraries(resolve_facts_llvm PUBLIC
    resolve_facts
    facts_rs
    Threads::Threads
    ${CMAKE_DL_LIBS}
    m
)

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
    "${CMAKE_CURRENT_SOURCE_DIR}/src/reach/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/reach/*.hpp"
)

file(GLOB_RECURSE LIB
    "${CMAKE_CURRENT_SOURCE_DIR}/include/reach/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/reach/*.cpp"
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
    resolve_add_check_targets(libreach ${LIB})
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
