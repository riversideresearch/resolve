# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

# Add LLVM headers to include search paths
find_package(LLVM 18.1.3 CONFIG)
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

add_subdirectory(libresolve)

# Build Targets
add_library(CVEAssert SHARED 
  src/arith_san.cpp
  src/bounds_check.cpp
  src/CVEAssert.cpp
  src/helpers.cpp
  src/instrument.cpp
  src/null_ptr.cpp
  src/undesirableop.cpp
)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(CVEAssert PRIVATE -fno-rtti)
endif()

if(COMMAND resolve_add_check_targets)
  resolve_add_check_targets(CVEAssert ${SRC})
endif()

# Test Targets
add_custom_target(test-CVEAssert 
    DEPENDS test-CVEAssert-lit test-CVEAssert-juliet
)

add_custom_target(test-CVEAssert-lit
    COMMAND
      ${CMAKE_COMMAND} -E env 
        RESOLVE_TEST_CVEASSERT_LIB=$<TARGET_FILE:CVEAssert>
        RESOLVE_TEST_LIBRESOLVE_LIBRARY_PATH=${LIBRESOLVE_LIBRARY_PATH}
        
    lit -v ${CMAKE_CURRENT_SOURCE_DIR}/tests/lit/
    DEPENDS CVEAssert
    COMMENT "Running lit regression tests for CVEAssert"
)

add_custom_target(test-CVEAssert-juliet
    COMMAND ${CMAKE_COMMAND} -E env
      # Ensure resolvecc is in path
      "PATH=${CMAKE_SOURCE_DIR}/resolve-cc/bin:$ENV{PATH}"
      # We haven't installed yet, so manually provide all the build paths
      "RESOLVE_LIB_DIR=${LIBRESOLVE_LIBRARY_PATH}"
      "RESOLVE_FACTS_PLUGIN=$<TARGET_LINKER_FILE:ResolveFactsPlugin>"
      "RESOLVE_CVEASSERT_PLUGIN=$<TARGET_FILE:CVEAssert>"
      python3 -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/juliet/resolve_juliet.py -f --assert_coverage_greater 30
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/tests/juliet/resolve_juliet.py ${CMAKE_CURRENT_SOURCE_DIR}/tests/juliet/testcases.tar.xz
    DEPENDS CVEAssert
    COMMENT "Running juilet coverage tests for CVEAssert"
)

#Install 
install(TARGETS CVEAssert EXPORT resolve_targets)
