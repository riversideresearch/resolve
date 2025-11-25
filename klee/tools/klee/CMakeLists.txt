#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
add_executable(klee
  main.cpp
)

set(KLEE_LIBS
  kleeCore
)

add_library(EnhancedFacts UNKNOWN IMPORTED)
set_target_properties(EnhancedFacts PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../llvm-plugin/build/libEnhancedFactsStatic.so")

target_link_libraries(klee ${KLEE_LIBS} reachlib resolve EnhancedFacts LLVM)
#target_link_directories(klee ${RESOLVE_BUILD_DIR})
target_include_directories(klee PRIVATE ${KLEE_INCLUDE_DIRS} ${LLVM_INCLUDE_DIRS} ${RESOLVE_SOURCE_DIR} ${RESOLVE_BUILD_DIR})
target_compile_options(klee PRIVATE ${KLEE_COMPONENT_CXX_FLAGS})
target_compile_definitions(klee PRIVATE ${KLEE_COMPONENT_CXX_DEFINES})


install(TARGETS klee RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(klee BuildKLEERuntimes)
