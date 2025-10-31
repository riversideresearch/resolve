#/bin/bash

# Ensure the parent repo has been built before running
make -C "../"

# get the OpenSSL repo
if [ ! -d "openssl" ]; then
    git clone https://github.com/openssl/openssl.git
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

mkdir openssl_facts

# Extract the embedded info from the openssl binary

python3 ../linker/AnalysisEngine_linkmap.py --in_bin=openssl/libssl.so --out_dir=openssl_facts

