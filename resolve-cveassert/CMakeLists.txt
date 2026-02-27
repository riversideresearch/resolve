# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

add_subdirectory(libresolve)

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

if(COMMAND resolve_add_check_targets)
  resolve_add_check_targets(CVEAssert ${SRC})
endif()

# Test Targets
add_custom_target(test-CVEAssert 
    COMMAND
      ${CMAKE_COMMAND} -E env 
        RESOLVE_TEST_CVEASSERT_LIB=$<TARGET_FILE:CVEAssert>
        RESOLVE_TEST_LIBRESOLVE_LIBRARY_PATH=${LIBRESOLVE_LIBRARY_PATH}
        
    lit -v ${CMAKE_CURRENT_SOURCE_DIR}/tests/
    DEPENDS CVEAssert
    COMMENT "Running regression tests for CVEAssert"
)

# Install
install(TARGETS CVEAssert EXPORT resolve_targets)
install(DIRECTORY bin/ DESTINATION ${CMAKE_INSTALL_BINDIR}
  FILE_PERMISSIONS
    OWNER_READ OWNER_EXECUTE OWNER_WRITE
    GROUP_READ GROUP_EXECUTE
    WORLD_READ WORLD_EXECUTE
)