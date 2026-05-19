#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

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

mkdir -p "$SCRIPT_DIR/build"
cd "$SCRIPT_DIR/build"

cmake ..
make # produces resolve-patch.ll

echo "-----------------"
echo "Running original:"
echo "-----------------"

./main || true

# ensure llvm-mctoll in path
export PATH="$SCRIPT_DIR/../llvm-mctoll/llvm-project/build/bin:$PATH"

# creates main-dis.ll
llvm-mctoll main

echo "-----------------"
echo "Running patcher:"
echo "-----------------"

# run our patcher
../../patcher.py -i main-dis.ll -p resolve-patch.ll -o main-patched.ll

# recompile
clang main-patched.ll -o main-patched

echo "-----------------"
echo "Running patched:"
echo "-----------------"

./main-patched