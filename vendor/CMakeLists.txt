add_subdirectory(argparse)
add_subdirectory(json)

install(TARGETS json EXPORT vendor_targets)
install(DIRECTORY json/include/json DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT vendor_targets 
    FILE ResolveVendorTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Resolve
)
