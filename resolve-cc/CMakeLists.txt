# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/hooks/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/hooks/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

# Build Targets
add_subdirectory(hooks)

add_library(ResolveFactsPlugin SHARED src/ResolveFactsPluginPass.cpp)
target_link_libraries(ResolveFactsPlugin PRIVATE resolve_facts_llvm)

# LLVM is normally built without RTTI. Be consistent with that.
if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(ResolveFactsPlugin PRIVATE -fno-rtti)
endif()

if(COMMAND resolve_add_check_targets)
  resolve_add_check_targets(ResolveFactsPlugin ${SRC})
endif()

install(TARGETS ResolveFactsPlugin EXPORT resolve_targets)
