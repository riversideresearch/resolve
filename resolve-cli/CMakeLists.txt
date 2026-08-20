# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

# Build the reachability command.
find_program(CARGO_EXECUTABLE cargo REQUIRED)

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CARGO_PROFILE debug)
    set(CARGO_FLAGS)
else()
    set(CARGO_PROFILE release)
    set(CARGO_FLAGS --release)
endif()

set(CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")

# Build resolve-reach separately (needs C++ libs)
set(REACH_CRATE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/resolve/reach")
set(REACH_BINARY "${CARGO_TARGET_DIR}/${CARGO_PROFILE}/resolve-reach")
set(REACH_CARGO_ENV
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "RESOLVE_LIBREACH_DIR=$<TARGET_FILE_DIR:libreach>"
)

add_custom_target(resolve-reach ALL
    COMMAND ${CMAKE_COMMAND} -E env
        ${REACH_CARGO_ENV}
        ${CARGO_EXECUTABLE} build --locked ${CARGO_FLAGS} --bin resolve-reach
    WORKING_DIRECTORY "${REACH_CRATE_DIR}"
    BYPRODUCTS "${REACH_BINARY}"
    DEPENDS libreach
    COMMENT "Building resolve-reach (Rust with C++ deps)"
    USES_TERMINAL
    VERBATIM
)

# Build all other Rust CLI binaries (no C++ dependencies)
set(CLI_BINARIES
    resolve
    resolve-get-facts
    resolve-remediate
    resolve-crash-analysis
    resolve-input-synthesis
    resolve-input-synthesis-setup
    resolve-input-synthesis-improve-cve
    resolve-input-synthesis-reachability
    resolve-input-synthesis-synthesize
    resolve-input-synthesis-run-all
    resolve-sbom
)

add_custom_target(resolve-cli-binaries ALL
    COMMAND ${CMAKE_COMMAND} -E env
        CARGO_TARGET_DIR=${CARGO_TARGET_DIR}
        ${CARGO_EXECUTABLE} build --locked ${CARGO_FLAGS}
        --bin resolve
        --bin resolve-get-facts
        --bin resolve-remediate
        --bin resolve-crash-analysis
        --bin resolve-input-synthesis
        --bin resolve-input-synthesis-setup
        --bin resolve-input-synthesis-improve-cve
        --bin resolve-input-synthesis-reachability
        --bin resolve-input-synthesis-synthesize
        --bin resolve-input-synthesis-run-all
        --bin resolve-sbom
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Building resolve CLI binaries (Rust)"
    USES_TERMINAL
    VERBATIM
)

# Install all Rust binaries
install(PROGRAMS "${REACH_BINARY}" DESTINATION "${CMAKE_INSTALL_BINDIR}")

foreach(binary ${CLI_BINARIES})
    install(PROGRAMS "${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${binary}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}")
endforeach()

# Install prompt templates
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/prompts"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/resolve"
    FILES_MATCHING PATTERN "*.txt")

add_custom_target(test-resolve-reach
    COMMAND ${CMAKE_COMMAND} -E env
        ${REACH_CARGO_ENV}
        ${CARGO_EXECUTABLE} test --locked
    WORKING_DIRECTORY "${REACH_CRATE_DIR}"
    DEPENDS libreach
    COMMENT "Running the resolve-reach tests"
    USES_TERMINAL
    VERBATIM
)
