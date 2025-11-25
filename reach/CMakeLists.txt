cmake_minimum_required(VERSION 3.22)
project(reach)

add_subdirectory(lib)

# set (CMAKE_CXX_STANDARD 23)
set (CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_COMPILER "clang++")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=3 -fpass-plugin=${CMAKE_SOURCE_DIR}/../llvm-plugin/build/libEnhancedFacts.so")

add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE reachlib)
