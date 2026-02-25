
add_subdirectory(../reach reach)

include(ExternalProject)

# Detect CPU count for parallel builds
include(ProcessorCount)
ProcessorCount(NPROC)

set(KLEE_UCLIBC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install/klee-uclibc)
set(KLEE_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install/klee)

ExternalProject_Add(klee_uclibc
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../klee-uclibc-160
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/klee-uclibc-build

    # Copy source into build dir before configuring
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E copy_directory <SOURCE_DIR> <BINARY_DIR> &&
        cd <BINARY_DIR> &&
        ./configure
            --make-llvm-lib
            --with-cc clang-16
            --with-llvm-config llvm-config-16

    BUILD_COMMAND
        make -C <BINARY_DIR> -j${NPROC}

    INSTALL_DIR ${KLEE_UCLIBC_INSTALL_DIR}
    INSTALL_COMMAND
        ${CMAKE_COMMAND} -E make_directory <INSTALL_DIR> &&
        ${CMAKE_COMMAND} -E copy_directory <BINARY_DIR>/lib <INSTALL_DIR>/lib &&
        ${CMAKE_COMMAND} -E copy_directory <BINARY_DIR>/include <INSTALL_DIR>/include
)

ExternalProject_Add(klee
    DEPENDS klee_uclibc libreach resolve_facts_llvm

    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../klee
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/klee-build

    CONFIGURE_COMMAND
        ${CMAKE_COMMAND}
            -S <SOURCE_DIR>
            -B <BINARY_DIR>
            -DCMAKE_INSTALL_PREFIX=${KLEE_INSTALL_DIR}
            -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
            -DLLVM_DIR=/usr/lib/llvm-16
            -DCMAKE_BUILD_TYPE=Release
            -DENABLE_SOLVER_STP=OFF
            -DENABLE_SOLVER_Z3=ON
            -DENABLE_POSIX_RUNTIME=ON
            -DKLEE_UCLIBC_PATH=${KLEE_UCLIBC_INSTALL_DIR}
            -DENABLE_UNIT_TESTS=OFF
            -DENABLE_KLEE_ASSERTS=OFF
            -DKLEE_RUNTIME_BUILD_TYPE=Release

    BUILD_COMMAND
        ${CMAKE_COMMAND} --build <BINARY_DIR> -- -j${NPROC}

    INSTALL_DIR ${KLEE_INSTALL_DIR}
    INSTALL_COMMAND
        ${CMAKE_COMMAND} --build <BINARY_DIR> --target install
)
