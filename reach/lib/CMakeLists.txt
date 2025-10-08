add_library(reachlib distmap.cpp facts.cpp graph.cpp search.cpp util.cpp)

target_include_directories(reachlib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_compile_features(reachlib PUBLIC cxx_std_23)
