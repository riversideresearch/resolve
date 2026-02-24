
find_package(LLVM 18.1.3 CONFIG)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20 STRING "")

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/**/*.hpp"
)

# Build Targets
add_library(resolve_facts_llvm STATIC src/resolve_facts_llvm.cpp)
target_link_libraries(resolve_facts_llvm PUBLIC resolve_facts)

target_include_directories(resolve_facts_llvm PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
set_target_properties(resolve_facts_llvm PROPERTIES POSITION_INDEPENDENT_CODE ON)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(resolve_facts_llvm PRIVATE -fno-rtti)
endif()

resolve_add_check_targets(resolve_facts_llvm ${SRC})
