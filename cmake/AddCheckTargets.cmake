# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

# Ensure the global umbrella targets exist
if(NOT TARGET check)
    add_custom_target(check
        COMMENT "Running all code quality checks"
    )
endif()

if(NOT TARGET check-format)
    add_custom_target(check-format
        COMMENT "Running all code format checks"
    )
endif()

# Add standard c/c++ check targets for target_name with sources
function(resolve_add_check_targets target_name)
    # Remaining arguments are the source files
    set(sources ${ARGN})

    if(sources STREQUAL "")
        message(WARNING "resolve_add_check_targets(${target_name}) called with no sources")
    endif()

    # Target: auto-format files
    add_custom_target(format-${target_name}
        COMMAND clang-format -i ${sources}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running clang-format on ${target_name}"
        VERBATIM
    )

    # Target: check formatting (no modifications)
    add_custom_target(check-format-${target_name}
        COMMAND clang-format --dry-run --Werror ${sources}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running clang-format checks on ${target_name}"
    )

    # Target: run clang-tidy
    # Skip this for c++ 23 target because glaze uses some features that llvm-18 doesn't supply
    get_target_property(target_std ${target_name} CXX_STANDARD)
    message("${target_name} @ ${target_std}")
    if (target_std AND target_std GREATER_EQUAL 23)
        add_custom_target(lint-${target_name}
            COMMAND true
            COMMENT "Skipping clang-tidy checks for cxx_23+ ${target_name}"
        )
    else()
        add_custom_target(lint-${target_name}
            COMMAND clang-tidy
                    -p ${CMAKE_BINARY_DIR}
                    ${sources}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Running clang-tidy checks on ${target_name}"
        )
    endif()

    # Needed by clang tidy
    set_target_properties(${target_name} PROPERTIES EXPORT_COMPILE_COMMANDS ON)

    # Combined check target
    add_custom_target(check-${target_name}
        DEPENDS check-format-${target_name} lint-${target_name}
        COMMENT "Running all code quality checks"
    )

    # Register under the global umbrella targets
    add_dependencies(check-format check-format-${target_name})
    add_dependencies(check check-${target_name})
endfunction()
