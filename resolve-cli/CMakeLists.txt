# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

set(RESOLVE_PYTHON_VERSION "3.12" CACHE STRING "Python version used for the resolve CLI environment")
option(RESOLVE_BUNDLE_PYTHON "Install a uv-managed Python into the resolve install prefix" OFF)

# Make the install prefix a Python environment for the resolve CLI tools.
install(CODE "
    set(_resolve_python_version \"${RESOLVE_PYTHON_VERSION}\")
    set(_resolve_bundle_python \"${RESOLVE_BUNDLE_PYTHON}\")

    set(_install_prefix \"\${CMAKE_INSTALL_PREFIX}\")
    if(DEFINED ENV{DESTDIR} AND NOT \"\$ENV{DESTDIR}\" STREQUAL \"\")
        if(IS_ABSOLUTE \"\${_install_prefix}\")
            set(_install_prefix \"\$ENV{DESTDIR}\${_install_prefix}\")
        else()
            set(_install_prefix \"\$ENV{DESTDIR}/\${_install_prefix}\")
        endif()
    endif()

    file(MAKE_DIRECTORY \"\${_install_prefix}/bin\")

    if(_resolve_bundle_python)
        set(_python_install_dir \"\${_install_prefix}/python\")
        message(STATUS \"Installing uv-managed Python \${_resolve_python_version} into \${_python_install_dir}\")
        execute_process(
            COMMAND uv python install \"\${_resolve_python_version}\" --install-dir \"\${_python_install_dir}\" --no-bin
            COMMAND_ERROR_IS_FATAL ANY
        )

        file(GLOB _managed_python_candidates
            \"\${_python_install_dir}/*/bin/python\${_resolve_python_version}\"
            \"\${_python_install_dir}/*/bin/python3\"
            \"\${_python_install_dir}/*/bin/python\"
        )
        list(LENGTH _managed_python_candidates _managed_python_count)
        if(_managed_python_count EQUAL 0)
            message(FATAL_ERROR \"uv did not install a Python interpreter under \${_python_install_dir}\")
        endif()
        list(GET _managed_python_candidates 0 _uv_python_path)
    else()
        set(_uv_python_path \"\${_resolve_python_version}\")
    endif()

    message(STATUS \"Creating resolve Python environment at \${_install_prefix}\")
    execute_process(
        COMMAND uv venv --allow-existing --relocatable --python \"\${_uv_python_path}\" \"\${_install_prefix}\"
        COMMAND_ERROR_IS_FATAL ANY
    )
")

# Stamp the resolve version into the package before installing it
install(CODE "
    set(_resolve_version \"\")
    if(\"\$ENV{GITHUB_REF_TYPE}\" STREQUAL \"tag\" AND NOT \"\$ENV{GITHUB_REF_NAME}\" STREQUAL \"\")
        set(_resolve_version \"\$ENV{GITHUB_REF_NAME}\")
    else()
        execute_process(
            COMMAND git -C \"${CMAKE_CURRENT_SOURCE_DIR}\" describe --tags --always --dirty --abbrev=8
            RESULT_VARIABLE _git_result
            OUTPUT_VARIABLE _git_version
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(_git_result EQUAL 0)
            set(_resolve_version \"\${_git_version}\")
        endif()
    endif()
    message(STATUS \"Stamping resolve version: '\${_resolve_version}'\")
    file(WRITE \"${CMAKE_CURRENT_SOURCE_DIR}/src/resolve/_version.py\"
\"# Generated at build/install time by resolve-cli/CMakeLists.txt. Do not edit or commit.
__version__ = \\\"\${_resolve_version}\\\"
\")
")

# Install as python package with uv
install(CODE "
    set(_install_prefix \"\${CMAKE_INSTALL_PREFIX}\")
    if(DEFINED ENV{DESTDIR} AND NOT \"\$ENV{DESTDIR}\" STREQUAL \"\")
        if(IS_ABSOLUTE \"\${_install_prefix}\")
            set(_install_prefix \"\$ENV{DESTDIR}\${_install_prefix}\")
        else()
            set(_install_prefix \"\$ENV{DESTDIR}/\${_install_prefix}\")
        endif()
    endif()

    message(STATUS \"Installing resolve-triage python package with uv pip install...\")
    execute_process(
        COMMAND uv pip install --compile-bytecode --python \"\${_install_prefix}\" \"${CMAKE_CURRENT_SOURCE_DIR}\"
        RESULT_VARIABLE _uv_result
    )
    if(NOT _uv_result EQUAL 0)
        message(FATAL_ERROR \"uv pip install failed with exit code \${_uv_result}\")
    endif()
")
