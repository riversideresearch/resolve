cmake_minimum_required(VERSION 3.20)
project(resolve)

include(${CMAKE_SOURCE_DIR}/cmake/AddCheckTargets.cmake)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/opt/resolve" CACHE PATH "Resolve Install Location" FORCE)
endif()

include(GNUInstallDirs)

# Add LLVM headers to include search paths
find_package(LLVM 18.1.3 CONFIG)
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20 STRING "")

add_subdirectory(vendor)

add_subdirectory(reach)
add_subdirectory(resolve-cc)
add_subdirectory(resolve-cveassert)
add_subdirectory(resolve-facts)

install(EXPORT resolve_targets 
    FILE ResolveTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)

# Klee

