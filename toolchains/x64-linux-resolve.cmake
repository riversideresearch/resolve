set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# Path to our custom toolchain file (relative to the vcpkg root)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE /opt/toolchain/resolve-toolchain.cmake)

