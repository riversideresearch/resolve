
find_package(LLVM 18.1.3 CONFIG)

# Add LLVM headers to include search paths
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 20 STRING "")

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()


# Build Targets
add_library(resolve_facts STATIC IMPORTED GLOBAL)
set_target_properties(resolve_facts PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../resolve-facts/build/libs/resolve_facts/libresolve_facts.a")
set_target_properties(resolve_facts PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../resolve-facts/libs/resolve_facts/src/")
set_target_properties(resolve_facts PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(resolve_facts_llvm STATIC src/resolve_facts_llvm.cpp)
target_link_libraries(resolve_facts_llvm PUBLIC resolve_facts)

target_include_directories(resolve_facts_llvm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(resolve_facts_llvm PROPERTIES POSITION_INDEPENDENT_CODE ON)
