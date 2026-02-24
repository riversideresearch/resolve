add_subdirectory(libs/resolve_facts)
add_subdirectory(libs/resolve_facts_llvm)

install(TARGETS resolve_facts resolve_facts_llvm EXPORT resolve_facts_targets)
install(DIRECTORY libs/resolve_facts/include/resolve_facts DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY libs/resolve_facts_llvm/include/resolve_facts_llvm DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT resolve_facts_targets 
    FILE ResolveFactsTargets.cmake
    NAMESPACE Resolve::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Resolve
)
