#!/usr/bin/env bash
#
# Copyright (c) 2026 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <build-dir> <stage-dir> <tarball> <install-prefix>" >&2
    exit 2
fi

BUILD_DIR_INPUT=$1
STAGE_DIR_INPUT=$2
TARBALL_INPUT=$3
INSTALL_PREFIX=${4%/}

if [[ "$INSTALL_PREFIX" != /* ]]; then
    echo "error: install prefix must be absolute: $INSTALL_PREFIX" >&2
    exit 2
fi

BUILD_DIR=$(cd "$BUILD_DIR_INPUT" && pwd)
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARBALL_DIR=$(dirname "$TARBALL_INPUT")
TARBALL_NAME=$(basename "$TARBALL_INPUT")

cmake -E rm -rf "$STAGE_DIR_INPUT"
cmake -E make_directory "$STAGE_DIR_INPUT"
cmake -E make_directory "$TARBALL_DIR"

STAGE_DIR=$(cd "$STAGE_DIR_INPUT" && pwd)
TARBALL_DIR=$(cd "$TARBALL_DIR" && pwd)
TARBALL="$TARBALL_DIR/$TARBALL_NAME"
STAGED_PREFIX="${STAGE_DIR}${INSTALL_PREFIX}"

DESTDIR="$STAGE_DIR" cmake --install "$BUILD_DIR"

if [ ! -d "$STAGED_PREFIX" ]; then
    echo "error: expected staged install at $STAGED_PREFIX" >&2
    exit 1
fi

if [ ! -d "$STAGED_PREFIX/python" ]; then
    echo "error: release package expected bundled Python under $STAGED_PREFIX/python" >&2
    exit 1
fi

copy_runtime_library() {
    local soname=$1
    local candidate=

    for dir in /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu /usr/lib64 /usr/lib; do
        if [ -e "$dir/$soname" ]; then
            candidate="$dir/$soname"
            break
        fi
    done

    if [ -z "$candidate" ]; then
        echo "error: could not find runtime library $soname" >&2
        exit 1
    fi

    local target
    target=$(readlink -f "$candidate")
    cp -f "$target" "$STAGED_PREFIX/lib/$(basename "$target")"

    if [ "$(basename "$target")" != "$soname" ]; then
        ln -sfn "$(basename "$target")" "$STAGED_PREFIX/lib/$soname"
    fi
}

copy_runtime_library libstdc++.so.6
copy_runtime_library libgcc_s.so.1

MANAGED_PYTHON=$(
    find "$STAGED_PREFIX/python" -path "*/bin/python3*" -type f | sort | head -n 1
)

if [ -z "$MANAGED_PYTHON" ]; then
    echo "error: could not find bundled Python interpreter under $STAGED_PREFIX/python" >&2
    exit 1
fi

MANAGED_PYTHON_REL=${MANAGED_PYTHON#"$STAGED_PREFIX"/}
MANAGED_PYTHON_FINAL="$INSTALL_PREFIX/$MANAGED_PYTHON_REL"
PYTHON_MINOR=$(basename "$MANAGED_PYTHON")

ln -sfn "$MANAGED_PYTHON_FINAL" "$STAGED_PREFIX/bin/python"
ln -sfn python "$STAGED_PREFIX/bin/python3"
ln -sfn python "$STAGED_PREFIX/bin/$PYTHON_MINOR"

if [ -f "$STAGED_PREFIX/pyvenv.cfg" ]; then
    sed -i "s|$STAGED_PREFIX|$INSTALL_PREFIX|g" "$STAGED_PREFIX/pyvenv.cfg"
fi

for file in "$STAGED_PREFIX"/bin/*; do
    [ -f "$file" ] || continue
    magic=$(head -c 2 "$file" || true)
    [ "$magic" = "#!" ] || continue
    first_line=$(sed -n '1p' "$file" || true)
    case "$first_line" in
        "#!"*"python"*)
            sed -i "1c#!$INSTALL_PREFIX/bin/python3" "$file"
            chmod +x "$file"
            ;;
    esac
done

cmake -E make_directory "$STAGE_DIR/usr/local/bin"
for cmd in "$STAGED_PREFIX"/bin/resolve* "$STAGED_PREFIX"/bin/reach "$STAGED_PREFIX"/bin/resolve_read_props; do
    [ -e "$cmd" ] || continue
    cmd_name=$(basename "$cmd")
    ln -sfn "$INSTALL_PREFIX/bin/$cmd_name" "$STAGE_DIR/usr/local/bin/$cmd_name"
done

cp "$REPO_ROOT/LICENSE.txt" "$STAGE_DIR/LICENSE.txt"
cp "$REPO_ROOT/LICENSE-GPL-3.0.txt" "$STAGE_DIR/LICENSE-GPL-3.0.txt"
tar -C "$STAGE_DIR" -czf "$TARBALL" opt usr LICENSE.txt LICENSE-GPL-3.0.txt

echo "Created $TARBALL"
echo "Install with: sudo tar -C / -xzf $TARBALL"
