
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

# Make install directory a pyvenv if it does not already contain a python interpreter
install(CODE "
    function(is_path_in_prefix INPUT_PATH RESULT_VAR)
        # Normalize both paths to absolute, real paths
        get_filename_component(_path_real \"\${INPUT_PATH}\" REALPATH)
        get_filename_component(_prefix_real \"\${CMAKE_INSTALL_PREFIX}\" REALPATH)

        # Check whether the input path begins with the prefix
        string(FIND \"\${_path_real}\" \"\${_prefix_real}\" _pos)

        if(_pos EQUAL 0)
            set(\${RESULT_VAR} TRUE PARENT_SCOPE)
        else()
            set(\${RESULT_VAR} FALSE PARENT_SCOPE)
        endif()
    endfunction()

    execute_process(
        COMMAND uv python find --project \"${CMAKE_CURRENT_SOURCE_DIR}\" \"\${CMAKE_INSTALL_PREFIX}\"
        RESULT_VARIABLE _uv_result
        OUTPUT_VARIABLE _uv_python_path
        ERROR_QUIET
    )
        
    if(_uv_result EQUAL 0)
        message(STATUS \"Python interpreter found in install prefix: \${_uv_python_path}\")
    else()
        message(STATUS \"No Python interpreter found in install prefix\")
        message(STATUS \"Creating a python venv at install prefix...\")
    
        execute_process(
            COMMAND uv python find --project \"${CMAKE_CURRENT_SOURCE_DIR}\"
            RESULT_VARIABLE _uv_result
            OUTPUT_VARIABLE _uv_python_path
        )
        
        string(STRIP \"\${_uv_python_path}\" _uv_python_path)

        message(STATUS \"Using python at \${_uv_python_path}\")
    
        # Link the main bin/python exe
        file(CREATE_LINK
            \"\${_uv_python_path}\"
            \"\${CMAKE_INSTALL_PREFIX}/bin/python\"
            SYMBOLIC
        )

        # Link bin/python3.x and bin/python3
        execute_process(
            COMMAND \"\${_uv_python_path}\" -I -c \"import sys; print('python{}.{}'.format(sys.version_info.major, sys.version_info.minor))\"
            OUTPUT_VARIABLE _py_exe
            COMMAND_ERROR_IS_FATAL ANY
        )
        string(STRIP \"\${_py_exe}\" _py_exe)
        file(CREATE_LINK
            \"\${_uv_python_path}\"
            \"\${CMAKE_INSTALL_PREFIX}/bin/\${_py_exe}\"
            SYMBOLIC
        )
        execute_process(
            COMMAND \"\${_uv_python_path}\" -I -c \"import sys; print('python{}'.format(sys.version_info.major))\"
            OUTPUT_VARIABLE _py_exe
            COMMAND_ERROR_IS_FATAL ANY
        )
        string(STRIP \"\${_py_exe}\" _py_exe)
        file(CREATE_LINK
            \"\${_uv_python_path}\"
            \"\${CMAKE_INSTALL_PREFIX}/bin/\${_py_exe}\"
            SYMBOLIC
        )

        # Create pyvenv.cfg
        message(STATUS \"Creating pyvenv.cfg\")
        cmake_path(GET _uv_python_path PARENT_PATH _python_home)

        file(WRITE
            \"\${CMAKE_INSTALL_PREFIX}/pyvenv.cfg\" \"home = \${_python_home}\\n\"
        )

    endif()
")

# Install as python package with uv
install(CODE "
    message(STATUS \"Installing resolve-triage python package with uv pip install...\")
    execute_process(
        COMMAND uv pip install --compile-bytecode --python \"\${CMAKE_INSTALL_PREFIX}\" \"${CMAKE_CURRENT_SOURCE_DIR}\"
        RESULT_VARIABLE _uv_result
    )
    if(NOT _uv_result EQUAL 0)
        message(FATAL_ERROR \"uv pip install failed with exit code \${_uv_result}\")
    endif()
")
