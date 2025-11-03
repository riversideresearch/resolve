#/bin/bash
set -e -v

ROOT_DIR="$(dirname $(pwd))"
EFACTS_LIB="$ROOT_DIR/llvm-plugin/build/libEnhancedFacts.so"

# Ensure the parent repo has been built before running
make -C "../"

# get the rust repo repo
if [ ! -d "rust" ]; then
    git clone --depth=1 https://github.com/rust-lang/rust.git
fi

cd rust 

# configure will abort if a bootstrap file is found from a previous run
if [ -f "bootstrap.toml" ]; then
    rm bootstrap.toml
fi


# ensure we build with clang to use the plugin
export CC=clang
export CXX=clang++

# configure rust to build llvm with plugin support enabled
./configure --release-channel=nightly --set llvm.plugins=true \
    --set llvm.cflags="-fpass-plugin=$EFACTS_LIB" \
    --set llvm.cxxflags="-fpass-plugin=$EFACTS_LIB" \
    --set target.x86_64-unknown-linux-gnu.cc="clang" \
    --set target.x86_64-unknown-linux-gnu.cxx="clang++" \
    --set target.x86_64-unknown-linux-gnu.linker="clang" \

# build the rust compiler
# Attempt to run the EnhancedFacts plugin on rust binaries themselves, 
# only after initialbootstrapping has finished so that the compiler has plugin support enabled
#
# This does build llvm with enhanced facts and its binaries can be found in build/x86_64-unknown-linux-gnu/llvm/bin
RUSTFLAGS_NOT_BOOTSTRAP="-Z llvm-plugins=$EFACTS_LIB" python3 x.py build --stage 1

# NOTE: right now running the enhanced facts plugin does not work rust rustc or the in-tree llvm, 
# probably due to ABI differences inbetween the system LLVM and bundled llvm (18 vs 21).
# The plugin will load with the current invocation, however it will nearly immediately segfault.

# Ensure we build new facts
if [ -d "llvm_facts" ]; then
    rm -rf llvm_facts 
fi
mkdir llvm_facts

# Extract the embedded info from the llvm opt binary

# Commented out right now since this generates approximately 120GB of output
#python3 ../linker/AnalysisEngine_linkmap.py --in_bin=rust/build/x86_64-unknown-linux-gnu/llvm/bin/opt --out_dir=llvm_facts

