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

set(RESOLVE_LLVM_PLUGIN_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../llvm-plugin/src")

target_link_libraries(klee ${KLEE_LIBS} reachlib glaze::glaze)
target_include_directories(klee PRIVATE ${KLEE_INCLUDE_DIRS} ${LLVM_INCLUDE_DIRS} ${RESOLVE_SOURCE_DIR} ${RESOLVE_BUILD_DIR}
  ${RESOLVE_LLVM_PLUGIN_INCLUDE_DIR})
target_compile_options(klee PRIVATE ${KLEE_COMPONENT_CXX_FLAGS})
target_compile_definitions(klee PRIVATE ${KLEE_COMPONENT_CXX_DEFINES})


install(TARGETS klee RUNTIME DESTINATION bin)

# The KLEE binary depends on the runtimes
add_dependencies(klee BuildKLEERuntimes)
