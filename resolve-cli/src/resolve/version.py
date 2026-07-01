# Copyright (c) 2025-2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

"""Resolution of the RESOLVE version string.

The most canon version is the git tag the release was built with, but for builds
this doesn't apply to, we fall back through the following:

1. "git describe"
2. Package metadata
3. unknown

CMake is responsible for generating ${CMAKE_CURRENT_SOURCE_DIR}/src/resolve/_version.py,
where the version is stamped in at build time.
"""

from __future__ import annotations


def get_version() -> str:
    """Return the RESOLVE version string. Never raises."""
    # Build-stamped version (CI builds)
    try:
        from resolve._version import __version__ as stamped

        if stamped:
            return stamped
    except Exception:
        pass

    # git describe: local builds.
    try:
        import subprocess
        from pathlib import Path

        result = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty", "--abbrev=8"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=2,
        )
        described = result.stdout.strip()
        if result.returncode == 0 and described:
            return described
    except Exception:
        pass

    # fallback: package metadata
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("resolve-cli")
        except PackageNotFoundError:
            pass
    except Exception:
        pass

    # wtf
    return "0.0.0+unknown"
