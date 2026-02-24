
include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_library(resolve_facts STATIC src/resolve_facts.cpp)
target_include_directories(resolve_facts PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(resolve_facts PRIVATE glaze::glaze)

# Requires PIC because we want to embedd in shared objects
set_target_properties(resolve_facts PROPERTIES POSITION_INDEPENDENT_CODE ON)

# glaze features need cxx 23
target_compile_features(resolve_facts PUBLIC cxx_std_23)