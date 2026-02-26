cmake_minimum_required(VERSION 3.20)
project(resolve-facts)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(${CMAKE_SOURCE_DIR}/../cmake/AddCheckTargets.cmake)

    # Add LLVM headers to include search paths
    find_package(LLVM 18.1.3 CONFIG)
    include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

    set(CMAKE_CXX_STANDARD 20 STRING "")

endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(libs/resolve_facts)
add_subdirectory(libs/resolve_facts_llvm)

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
