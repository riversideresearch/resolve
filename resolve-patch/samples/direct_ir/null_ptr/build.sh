#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PATCH_DIR="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
ROOT_DIR="$(cd -- "$PATCH_DIR/.." && pwd)"

RESOLVE_CC_LIB="$ROOT_DIR/build/resolve-cc"
CVEASSERT_LIB="$ROOT_DIR/build/resolve-cveassert"
LIBRESOLVE_LIB="$ROOT_DIR/build/resolve-cveassert/libresolve/libresolve-build/debug"
RESOLVE_LIB_DIR="$ROOT_DIR/resolve-cc/lib"

mkdir -p "$RESOLVE_LIB_DIR" "$SCRIPT_DIR/build"

ln -sf "$RESOLVE_CC_LIB/libResolveFactsPlugin.so" \
       "$RESOLVE_LIB_DIR/libResolveFactsPlugin.so"
ln -sf "$CVEASSERT_LIB/libCVEAssert.so" \
       "$RESOLVE_LIB_DIR/libCVEAssert.so"
ln -sf "$LIBRESOLVE_LIB/libresolve.so" \
       "$RESOLVE_LIB_DIR/libresolve.so"

export LD_LIBRARY_PATH="$RESOLVE_CC_LIB:$CVEASSERT_LIB:$LIBRESOLVE_LIB:$RESOLVE_LIB_DIR:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="$LIBRESOLVE_LIB:$RESOLVE_CC_LIB:$CVEASSERT_LIB:$RESOLVE_LIB_DIR:${LIBRARY_PATH:-}"
export PATH="$PATCH_DIR/llvm-mctoll/llvm-project/build/bin:$PATH"

cd "$SCRIPT_DIR/build"
rm -f main main-dis.ll main-instrumented.ll main-instrumented

clang -O0 -fno-pie -no-pie ../main.c -o main

echo "-----------------"
echo "Running original:"
echo "-----------------"
./main || true

llvm-mctoll -I "$PATCH_DIR/samples/mctoll-prototypes.h" main

echo "----------------------------------"
echo "Running CVEAssert on main-dis.ll:"
echo "----------------------------------"
"$ROOT_DIR/resolve-cc/bin/resolvecc" \
    -fno-resolve \
    -fcve-assert "$SCRIPT_DIR/vulnerabilities.json" \
    -S -emit-llvm main-dis.ll \
    -o main-instrumented.ll

echo "----------------------------------"
echo "Checking direct instrumentation:"
echo "----------------------------------"
if ! grep -q "__cve_null_check" main-instrumented.ll; then
    echo "direct-ir: expected null-check helpers were not emitted" >&2
    exit 1
fi
grep -n "__cve_null_check" main-instrumented.ll | head

clang main-instrumented.ll -o main-instrumented \
    -L"$LIBRESOLVE_LIB" \
    -Wl,--no-as-needed -lresolve -Wl,--as-needed \
    -Wl,-rpath="$LIBRESOLVE_LIB"

echo "---------------------"
echo "Running instrumented:"
echo "---------------------"
./main-instrumented || true
