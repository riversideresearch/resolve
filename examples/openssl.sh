#!/usr/bin/env bash

# TODO:
# Get build working first (done!)
# Add caching mechanism for openssl download (specifically for CI)

set -e 

# Gives the path to the current script file
# Changes directory and prints the absolute path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXTRACT_FACTS_SCRIPT="/opt/resolve/bin/extract_facts.py"
REACH_WRAPPER="/opt/resolve/bin/resolve-triage"

export CC="/usr/bin/clang"
export CXX="/usr/bin/clang++"
export CFLAGS="-fpass-plugin=/opt/resolve/lib/libResolveFactsPlugin.so"
export CXXFLAGS="$CFLAGS"
export PYTHONPATH="$REPO_ROOT/resolve-triage/src:$PYTHONPATH"
OPENSSL="https://github.com/openssl/openssl.git"

cd "$SCRIPT_DIR"

# -----------------
# Download OpenSSL
# -----------------
if [ ! -d "openssl" ]; then
    echo "[+] Downloading and building OpenSSL 3.5.0.\n"
    git clone --branch openssl-3.5.0 --depth 1 $OPENSSL
    cd openssl
    ./Configure && make -j
fi

cd "$SCRIPT_DIR"

# ----------------
# Fact extraction
# ---------------
echo "[+] Performing fact extraction.\n"
if [ -d "openssl_facts" ]; then
    rm -r openssl_facts
fi
mkdir openssl_facts

# NOTE: libcrypto.so is symlinked to libcrypto.so.3
"$EXTRACT_FACTS_SCRIPT" \
    --in_bin ./openssl/libcrypto.so.3 \
    --out_dir openssl_facts

# -------------------
# Run reach analysis
# -------------------
echo "[+] Running reachability analysis.\n" 
"$REACH_WRAPPER" \
    -i openssl_vulnerabilities.json \
    -o openssl_reach_out.json \
    -f openssl_facts \
    -e "CMS_RecipientInfo_decrypt" \
    -r /opt/resolve/bin/reach

# TODO: Add remediation portion check for exit code 3 for successful remediation