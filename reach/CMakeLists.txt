cmake_minimum_required(VERSION 3.22)
project(reach)

include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

set (CMAKE_CXX_STANDARD 23)
set (CMAKE_BUILD_TYPE Release)
#set (CMAKE_CXX_COMPILER "clang++")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=3")
#-fpass-plugin=${CMAKE_SOURCE_DIR}/../llvm-plugin/build/libEnhancedFacts.so")

add_subdirectory(lib)

add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE reachlib)
target_link_libraries(reach PRIVATE glaze::glaze)
