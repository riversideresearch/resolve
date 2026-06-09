# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

cmake_minimum_required(VERSION 3.20)
project(resolve)

include(${CMAKE_SOURCE_DIR}/cmake/AddCheckTargets.cmake)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/opt/resolve" CACHE PATH "Resolve Install Location" FORCE)
endif()

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20 STRING "")

add_subdirectory(resolve-cc)
add_subdirectory(resolve-cveassert)
add_subdirectory(resolve-facts)

option(RESOLVE_BUILD_KLEE "Build bundled KLEE support" OFF)
if(RESOLVE_BUILD_KLEE)
    include(${CMAKE_SOURCE_DIR}/cmake/InstallKlee.cmake)
endif()
add_subdirectory(resolve-cli)

install(EXPORT resolve_targets 
    FILE ResolveTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)
