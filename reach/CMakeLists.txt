# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/**/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
)

# reach lib
add_library(libreach 
    libs/reach/distmap.cpp
    libs/reach/facts.cpp
    libs/reach/graph.cpp
    libs/reach/search.cpp
    libs/reach/util.cpp
)

set_target_properties(libreach PROPERTIES OUTPUT_NAME "reach")

target_include_directories(libreach PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(libreach PUBLIC resolve_facts json)

target_compile_features(libreach PUBLIC cxx_std_23)

# reach executable
add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE libreach json argparse)

resolve_add_check_targets(reach ${SRC})
