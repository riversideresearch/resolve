cmake_minimum_required(VERSION 3.20)
project(resolve-facts)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

# Release with symbols by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(CMAKE_CXX_STANDARD 23 STRING "")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_library(ResolveFacts STATIC src/resolve_facts.cpp)
target_link_libraries(ResolveFacts PRIVATE glaze::glaze)
