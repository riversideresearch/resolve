cmake_minimum_required(VERSION 3.22)
project(reach)

set (CMAKE_CXX_STANDARD 23)
set (CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_COMPILER "clang++")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=3 -fpass-plugin=${CMAKE_SOURCE_DIR}/../llvm-plugin/build/libEnhancedFacts.so")

add_library(ResolveFacts STATIC IMPORTED GLOBAL)
set_target_properties(ResolveFacts PROPERTIES IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../resolve-facts/build/libResolveFacts.a")
set_target_properties(ResolveFacts PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../resolve-facts/src/")

add_subdirectory(lib)

add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE reachlib)
target_link_libraries(reach PRIVATE ResolveFacts)
