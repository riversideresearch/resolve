cmake_minimum_required(VERSION 3.20)
project(resolve-facts)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(${CMAKE_SOURCE_DIR}/../../cmake/AddCheckTargets.cmake)

    # Add LLVM headers to include search paths
    find_package(LLVM 18.1.3 CONFIG)
    include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

    set(CMAKE_CXX_STANDARD 20 STRING "")

endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/**/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

add_subdirectory(vendor/argparse)
add_subdirectory(vendor/json)

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
add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE libreach json argparse)

if(COMMAND resolve_add_check_targets)
    resolve_add_check_targets(reach ${SRC})
endif()

install(TARGETS reach libreach EXPORT reach_targets)
install(DIRECTORY include/reach DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT reach_targets 
    FILE ReachTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/ReachConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)

install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/ReachConfig.cmake"
        #   "${CMAKE_CURRENT_BINARY_DIR}/ReachConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/resolve
)
