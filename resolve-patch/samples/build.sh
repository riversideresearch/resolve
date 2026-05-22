#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
PATCH_DIR="$ROOT_DIR/resolve-patch"

RESOLVE_CC_LIB="$ROOT_DIR/build/resolve-cc"
CVEASSERT_LIB="$ROOT_DIR/build/resolve-cveassert"
LIBRESOLVE_LIB="$ROOT_DIR/build/resolve-cveassert/libresolve/libresolve-build/debug"

mkdir -p "$ROOT_DIR/resolve-cc/lib"

ln -sf "$RESOLVE_CC_LIB/libResolveFactsPlugin.so" \
       "$ROOT_DIR/resolve-cc/lib/libResolveFactsPlugin.so"
ln -sf "$CVEASSERT_LIB/libCVEAssert.so" \
       "$ROOT_DIR/resolve-cc/lib/libCVEAssert.so"
ln -sf "$LIBRESOLVE_LIB/libresolve.so" \
       "$ROOT_DIR/resolve-cc/lib/libresolve.so"

export LD_LIBRARY_PATH="$RESOLVE_CC_LIB:$CVEASSERT_LIB:$LIBRESOLVE_LIB:$ROOT_DIR/resolve-cc/lib:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="$LIBRESOLVE_LIB:$RESOLVE_CC_LIB:$CVEASSERT_LIB:$ROOT_DIR/resolve-cc/lib:${LIBRARY_PATH:-}"
export PATH="$PATCH_DIR/llvm-mctoll/llvm-project/build/bin:$PATH"

run_case() {
    local case_dir="$1"
    local abs_case="$SCRIPT_DIR/$case_dir"
    local build_dir="$abs_case/build"
    local patched_compiler="clang"
    local source_file="../main.c"

    if [[ ! -f "$abs_case/CMakeLists.txt" ]]; then
        echo "[samples] error: unknown sample '$case_dir'" >&2
        return 1
    fi

    if [[ -f "$abs_case/main.cpp" ]]; then
        patched_compiler="clang++"
        source_file="../main.cpp"
    fi

    echo "=============================="
    echo "[samples] $case_dir"
    echo "=============================="

    rm -rf "$build_dir"
    cmake -S "$abs_case" -B "$build_dir"
    cmake --build "$build_dir"

    (
        cd "$build_dir"

        "$patched_compiler" -O0 -fno-pie -no-pie "$source_file" -o main-original

        echo "-----------------"
        echo "Running original:"
        echo "-----------------"
        ./main-original || true

        echo "-------------------------------"
        echo "Generating mctoll prototypes:"
        echo "-------------------------------"
        python3 "$PATCH_DIR/prototype_gen.py" \
            -i main-original \
            -o mctoll-prototypes.generated.h

        llvm-mctoll -I mctoll-prototypes.generated.h main-original

        echo "-----------------"
        echo "Running patcher:"
        echo "-----------------"
        "$PATCH_DIR/patcher.py" \
            -i main-original-dis.ll \
            -p resolve-patch.ll \
            -o main-patched.ll


        "$patched_compiler" main-patched.ll -o main-patched \
            -L"$LIBRESOLVE_LIB" \
            -Wl,--no-as-needed -lresolve -Wl,--as-needed \
            -Wl,-rpath="$LIBRESOLVE_LIB"

        echo "-----------------"
        echo "Running patched:"
        echo "-----------------"
        ./main-patched || true
    )
}

if [[ "$#" -gt 0 ]]; then
    for case_dir in "$@"; do
        run_case "$case_dir"
    done
else
    for abs_case in "$SCRIPT_DIR"/c/* "$SCRIPT_DIR"/cpp/*; do
        [[ -d "$abs_case" ]] || continue
        run_case "${abs_case#"$SCRIPT_DIR/"}"
    done
fi
