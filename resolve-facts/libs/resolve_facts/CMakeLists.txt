
include(FetchContent)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG main
  GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(glaze)

add_library(resolve_facts STATIC src/resolve_facts.cpp)
target_link_libraries(resolve_facts PRIVATE glaze::glaze)

# Requires PIC?
set_target_properties(resolve_facts PROPERTIES POSITION_INDEPENDENT_CODE ON)

# glaze features need cxx 23
target_compile_features(resolve_facts PUBLIC cxx_std_23)