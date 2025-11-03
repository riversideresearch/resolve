#/bin/bash

OPENSSL="https://github.com/openssl/openssl.git"

# Ensure the parent repo has been built before running
make -C "../"

# get the OpenSSL repo
if [ ! -d "openssl" ]; then

#    git clone https://github.com/openssl/openssl.git
    git clone --branch openssl-3.5.0 --depth 1 $OPENSSL   
fi

cd openssl

# Set compiler flags to use the EnhancedFacts pass 
export CC=clang
export CXX=clang
export CFLAGS="-fpass-plugin=../../llvm-plugin/build/libEnhancedFacts.so"
export CXXFLAGS="$CFLAGS"
export LDLIBS="../../libresolve/target/debug/libresolve.so"

# Run OpenSSL's build
./Configure
make -j

# return to the examples folder
cd ..

# Ensure we build new facts
if [ -d "openssl_facts" ]; then
    rm openssl_facts
fi
mkdir openssl_facts

# Extract the embedded info from the openssl binary

python3 ../linker/AnalysisEngine_linkmap.py --in_bin=openssl/libcrypto.so --out_dir=openssl_facts

# Run the reach-wrapper tool
python3 ../reach-wrapper/reach-wrapper.py \
        -i openssl_vulnerabilities.json \
        -o openssl_reach_out.json \
        -f openssl_facts \
        -e "CMS_RecipientInfo_decrypt"
        -r ../reach/build/reach
