#!/usr/bin/env bash

# TODO:
# Get build working first
# Add caching mechanism for openssl download (specifically for CI)
# Get fact generation

set -e 

SCRIPT_DIR="${0%/*}"
EXTRACT_FACTS_SCRIPT="/opt/resolve/bin/extract_facts.py"
REACH_WRAPPER="/opt/resolve/bin/resolve-triage.py"

export CC="/usr/bin/clang"
export CXX="/usr/bin/clang++"
export CFLAGS="-fpass-plugin=/opt/resolve/lib/libResolveFactsPlugin.so"
export CXXFLAGS="$CFLAGS"
#export LDLIBS="/path/to/libresolve"
OPENSSL="https://github.com/openssl/openssl.git"

cd "$SCRIPT_DIR"

# get the OpenSSL repo
if [ ! -d "openssl" ]; then

#    git clone https://github.com/openssl/openssl.git
    git clone --branch openssl-3.5.0 --depth 1 $OPENSSL  
fi

cd openssl

# Run OpenSSL's build
./Configure
make -j

# return to the examples folder
cd ..

# Ensure we build new facts
if [ -d "openssl_facts" ]; then
    rm -r openssl_facts
fi
mkdir openssl_facts

# Extract the embedded info from the openssl binary
# Define the path to extract facts 
"$EXTRACT_FACTS_SCRIPT" --in_bin=openssl/libcrypto.so --out_dir=openssl_facts

# Run the reach-wrapper tool
"$REACH_WRAPPER" \
    -i openssl_vulnerabilities.json \
    -o openssl_reach_out.json \
    -f openssl_facts \
    -e "CMS_RecipientInfo_decrypt" \
    -r ../reach/build/reach

# TODO: Add remediation portion check for exit code 3 for successful remediation