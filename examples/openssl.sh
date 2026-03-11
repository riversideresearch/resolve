#!/usr/bin/env bash

# TODO:
# Get build working first
# Add caching mechanism for openssl download (specifically for CI)

set -e 

SCRIPT_DIR="${0%/*}"
CACHE_TAR="openssl-cache.tar.gz"

EXTRACT_FACTS_SCRIPT="/opt/resolve/bin/extract_facts.py"
REACH_WRAPPER="/opt/resolve/bin/resolve-triage"

export CC="/usr/bin/clang"
export CXX="/usr/bin/clang++"
export CFLAGS="-fpass-plugin=/opt/resolve/lib/libResolveFactsPlugin.so"
export CXXFLAGS="$CFLAGS"
OPENSSL="https://github.com/openssl/openssl.git"

cd "$SCRIPT_DIR"

# -----------------
# Download OpenSSL
# -----------------
git clone --branch openssl-3.5.0 --depth 1 $OPENSSL
cd openssl
./Configure && make -j 

if [ ! -f "libcrypto.so" ]; then
    make -j 
fi


cd ..

# -----------------------
# Fact extraction
# -----------------------
if [ -d "openssl_facts" ]; then
    rm -r openssl_facts
fi
mkdir openssl_facts

"$EXTRACT_FACTS_SCRIPT" \
    --in_bin ./openssl/libcrypto.so.3 \
    --out_dir openssl_facts

# -------------------
# Run reach analysis
# -------------------
export PYTHONPATH="/resolve/resolve-triage/src:$PYTHONPATH"

"$REACH_WRAPPER" \
    -i openssl_vulnerabilities.json \
    -o openssl_reach_out.json \
    -f openssl_facts \
    -e "CMS_RecipientInfo_decrypt" \
    -r /opt/resolve/bin/reach

# TODO: Add remediation portion check for exit code 3 for successful remediation