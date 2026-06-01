# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

include(GNUInstallDirs)
include(ExternalProject)
include(FetchContent)

# ### Pulling and building mimalloc project 
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG v3.3.2
)

# # Force static build 
set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MI_BUILD_STATIC ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(mimalloc)

target_sources(mimalloc-static PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/mimalloc_shadow.c
)
set(MIMALLOC_LIB_DIR ${mimalloc_BINARY_DIR})

set_target_properties(mimalloc-static PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# Map CMake build type to Cargo flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CARGO_PROFILE debug)
    set(CARGO_FLAGS "")
else()
    set(CARGO_PROFILE release)
    set(CARGO_FLAGS --release)
endif()

set(RUST_CRATE_DIR   ${CMAKE_CURRENT_SOURCE_DIR})
set(RUST_OUT_DIR   ${CMAKE_CURRENT_BINARY_DIR}/libresolve-build)
set(RUST_LIB ${RUST_OUT_DIR}/${CARGO_PROFILE}/libresolve.so)

set(LIBRESOLVE_LIBRARY_PATH ${RUST_OUT_DIR}/${CARGO_PROFILE} PARENT_SCOPE)

file(GLOB_RECURSE RUST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*")

add_custom_command(
    OUTPUT ${RUST_LIB}
    COMMAND 
        ${CMAKE_COMMAND} -E env
        CARGO_TARGET_DIR=${RUST_OUT_DIR}
        MIMALLOC_LIB_DIR=${MIMALLOC_LIB_DIR}
        cargo build ${CARGO_FLAGS} 
    WORKING_DIRECTORY ${RUST_CRATE_DIR}
    COMMENT "Building libresolve.so" VERBATIM
    DEPENDS mimalloc-static ${RUST_SOURCES} ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml ${CMAKE_CURRENT_SOURCE_DIR}/rust-toolchain.toml
)

add_custom_target(test-libresolve
    COMMAND cargo test
    WORKING_DIRECTORY ${RUST_CRATE_DIR}
    COMMENT "Running regression tests for libresolve"
)

add_custom_target(libresolve ALL DEPENDS ${RUST_LIB})
add_dependencies(libresolve mimalloc-static)
install(FILES ${RUST_LIB} DESTINATION ${CMAKE_INSTALL_LIBDIR})
