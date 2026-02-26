add_library(json INTERFACE)
target_include_directories(json INTERFACE 
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

install(TARGETS json EXPORT reach_targets)
install(DIRECTORY include/json DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
