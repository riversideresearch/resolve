include(GNUInstallDirs)
include(ExternalProject)

# Map CMake build type to Cargo flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "")
    set(CARGO_PROFILE debug)
    set(CARGO_FLAGS "")
else()
    set(CARGO_PROFILE release)
    set(CARGO_FLAGS --release)
endif()

set(RUST_OUT_DIR   ${CMAKE_CURRENT_BINARY_DIR}/libresolve)
set(RUST_LIB ${RUST_OUT_DIR}/${CARGO_PROFILE}/libresolve.so)

ExternalProject_Add(libresolve
    PREFIX          ${CMAKE_CURRENT_BINARY_DIR}
    SOURCE_DIR      ${CMAKE_CURRENT_SOURCE_DIR}
    BUILD_IN_SOURCE YES

    CONFIGURE_COMMAND ""
    INSTALL_COMMAND ""
    BUILD_COMMAND
        ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${RUST_OUT_DIR}
            cargo build ${CARGO_FLAGS}

    BUILD_BYPRODUCTS ${RUST_LIB}
)

install(FILES ${RUST_LIB} DESTINATION ${CMAKE_INSTALL_LIBDIR})
