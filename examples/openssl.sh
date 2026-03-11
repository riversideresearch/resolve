#!/usr/bin/env bash

# TODO:
# Get build working first
# Add caching mechanism for openssl download (specifically for CI)
# Get fact generation

set -e 

SCRIPT_DIR="${0%/*}"
CACHE_TAR="openssl-cache.tar.gz"

EXTRACT_FACTS_SCRIPT="/opt/resolve/bin/extract_facts.py"
REACH_WRAPPER="/opt/resolve/bin/resolve-triage"

export CC="/usr/bin/clang"
export CXX="/usr/bin/clang++"
export CFLAGS="-fpass-plugin=/opt/resolve/lib/libResolveFactsPlugin.so"
export CXXFLAGS="$CFLAGS"
#export LDLIBS="/path/to/libresolve"
OPENSSL="https://github.com/openssl/openssl.git"

cd "$SCRIPT_DIR"

# -----------------------
# Get OpenSSL from cache
# -----------------------
if [ -f "$CACHE_TAR" ]; then
    echo "[+] Using cached OpenSSL build"
    tar -xzf "$CACHE_TAR"
else 
    echo "[+] No cache found. Building OpenSSL..."

    git clone --branch openssl-3.5.0 --depth 1 $OPENSSL
    cd openssl

    ./Configure
    make -j 

    cd ..

    echo "[+] Creating cache archive"
    tar -czf "$CACHE_TAR" openssl
fi

# return to the examples folder
cd ..

# -----------------------
# Fact extraction
# -----------------------
if [ -d "openssl_facts" ]; then
    rm -r openssl_facts
fi
mkdir openssl_facts

"$EXTRACT_FACTS_SCRIPT" \ 
    --in_bin openssl/libcrypto.so \ 
    --out_dir openssl_facts

# -------------------
# Run reach analysis
# -------------------
"$REACH_WRAPPER" \
    -i openssl_vulnerabilities.json \
    -o openssl_reach_out.json \
    -f openssl_facts \
    -e "CMS_RecipientInfo_decrypt" \
    -r ../reach/build/reach

# TODO: Add remediation portion check for exit code 3 for successful remediation