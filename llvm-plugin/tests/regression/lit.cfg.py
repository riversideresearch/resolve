# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for licensing information.

import os
import lit.formats
import lit.util

# Name of test suite
config.name = "RESOLVE_SANITIZER_TEST"

# Source and execution root
config.test_source_root = os.path.dirname(__file__)
config.test_exec_root = config.test_source_root

# Treat files with RUN lines as shell-style tests
config.test_format = lit.formats.ShTest(True)

# Look up clang and FileCheck
clang = lit.util.which("clang")
filecheck = lit.util.which("FileCheck-18")

if not clang:
    lit.fatal("Could not find clang in PATH")

if not filecheck:
    lit.fatal("Could not find FileCheck-18 in PATH")

# Make substitutions in RUN lines of tests
config.substitutions.append(("%clang", clang))
config.substitutions.append(("%FileCheck", filecheck))

# Add path to pass plugin
plugin = "../../build/libCVEAssert.so"
config.substitutions.append(("%plugin", plugin))

# Add suffixes to test
config.suffixes = ['.c']