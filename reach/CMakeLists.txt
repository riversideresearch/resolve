add_subdirectory(lib)

add_executable(reach src/main.cpp)

target_link_libraries(reach PRIVATE reachlib)
