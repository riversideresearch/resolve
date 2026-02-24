# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

# Build Targets
add_library(CVEAssert SHARED 
  src/CVEAssert.cpp
  src/bounds_check.cpp
  src/null_ptr.cpp
  src/arith_san.cpp
  src/helpers.cpp
  src/undesirableop.cpp
)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(CVEAssert PRIVATE -fno-rtti)
endif()

resolve_add_check_targets(CVEAssert ${SRC})

# Test Targets
add_custom_target(test-CVEAssert 
    lit -v ${CMAKE_CURRENT_SOURCE_DIR}/tests/
    DEPENDS CVEAssert
    COMMENT "Running regression tests for CVEAssert"
)

# Install
install(TARGETS CVEAssert EXPORT resolve_cveassert_targets)

install(EXPORT resolve_cveassert_targets 
    FILE ResolveCVEAssertTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Resolve
)
