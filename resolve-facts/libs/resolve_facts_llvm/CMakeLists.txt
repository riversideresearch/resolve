
find_package(LLVM 18.1.3 CONFIG)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20 STRING "")


# Build Targets
add_library(resolve_facts_llvm STATIC src/resolve_facts_llvm.cpp)
target_link_libraries(resolve_facts_llvm PUBLIC resolve_facts)

target_include_directories(resolve_facts_llvm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(resolve_facts_llvm PROPERTIES POSITION_INDEPENDENT_CODE ON)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(resolve_facts_llvm PRIVATE -fno-rtti)
endif()
