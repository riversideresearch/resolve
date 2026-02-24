
include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

# Collect source files for checks
file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/**/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/**/*.hpp"
)

add_library(resolve_facts STATIC src/resolve_facts.cpp)
target_include_directories(resolve_facts PUBLIC 
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_link_libraries(resolve_facts PRIVATE glaze::glaze)

# Requires PIC because we want to embedd in shared objects
set_target_properties(resolve_facts PROPERTIES POSITION_INDEPENDENT_CODE ON)

# glaze features need cxx 23
target_compile_features(resolve_facts PUBLIC cxx_std_23)

resolve_add_check_targets(resolve_facts ${SRC})
