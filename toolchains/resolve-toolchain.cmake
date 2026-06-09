set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)

set(RESOLVE_PREFIX /opt/resolve)

set(RESOLVE_PLUGINS
  "-fpass-plugin=${RESOLVE_PREFIX}/lib/libResolveFactsPlugin.so -fpass-plugin=${RESOLVE_PREFIX}/lib/libCVEAssert.so"
)
    
# clang lowers mem* libc funtions into llvm intrinsics with additional metadata for optimization
# We want our CVEAssert sanitizers to see the original libc functions, so we ask clang to skip the special handling
# Ideally, we would only do that for vulnerable functions, but that requires behavior changes in clang or modifing source code
set(RESOLVE_INTRINSICS_FLAGS
  "-fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memset"
  )

# Keep basic debug info to make it eaiser to lookup function names and files for inlined functions
set(RESOLVE_DEBUG_INFO_FLAGS
  "-g1"
  )

set(CMAKE_C_FLAGS_INIT   "${CMAKE_C_FLAGS} ${RESOLVE_PLUGINS} ${RESOLVE_INTRINSICS_FLAGS} ${RESOLVE_DEBUG_INFO_FLAGS}" CACHE STRING "c flags")
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_CXX_FLAGS} ${RESOLVE_PLUGINS} ${RESOLVE_INTRINSICS_FLAGS} ${RESOLVE_DEBUG_INFO_FLAGS}" CACHE STRING "c++ flags")

set(RESOLVE_LIBRESOLVE_DIR "${RESOLVE_PREFIX}/lib")
set(RESOLVE_LIBRESOLVE_LINK_FLAGS
  "-L${RESOLVE_LIBRESOLVE_DIR} -lresolve -Wl,-rpath,${RESOLVE_LIBRESOLVE_DIR}"
)
set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} ${RESOLVE_LIBRESOLVE_LINK_FLAGS}")
set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} ${RESOLVE_LIBRESOLVE_LINK_FLAGS}")

# Force linker to link libresolve to work around dropping symbols in cmake compile tests
set(RESOLVE_RUNTIME_LINK
  "-Wl,--no-as-needed ${RESOLVE_LIBRESOLVE_LINK_FLAGS} -Wl,--as-needed"
)
set(CMAKE_EXE_LINKER_FLAGS_INIT
  "${CMAKE_EXE_LINKER_FLAGS_INIT} ${RESOLVE_RUNTIME_LINK}"
  CACHE STRING "Force link libresolve runtime"
)
set(CMAKE_SHARED_LINKER_FLAGS_INIT
  "${CMAKE_SHARED_LINKER_FLAGS_INIT} ${RESOLVE_RUNTIME_LINK}"
  CACHE STRING "Force link libresolve runtime"
)

# Needs to be manually specified for reasons we do not understand yet.
set(CMAKE_MAKE_PROGRAM "make" CACHE STRING "MakeFile Builder")
set(CMAKE_EXPERIMENTAL_FIND_CPS_PACKAGES "e82e467b-f997-4464-8ace-b00808fff261" CACHE STRING  "Load CPS files with find_package")
set(CMAKE_EXPERIMENTAL_EXPORT_PACKAGE_INFO "b80be207-778e-46ba-8080-b23bba22639e" CACHE STRING "Export CPS files")
set(CMAKE_EXPERIMENTAL_GENERATE_SBOM "ca494ed3-b261-4205-a01f-603c95e4cae0" CACHE STRING "Enable SBOM support")
set(CMAKE_INSTALL_SBOM_FORMATS "SPDX" CACHE STRING "Generate SBOM (SPDX) automatically")

message(STATUS "RESOLVE - Using custom Clang toolchain with SBOM")
