
#/bin/bash
set -e -v

ROOT_DIR="$(dirname $(pwd))"
EFACTS_LIB="$ROOT_DIR/llvm-plugin/build/libEnhancedFacts.so"

# Ensure the parent repo has been built before running
make -C "../"

# get the rust repo repo
if [ ! -d "llvm-project" ]; then
    git clone --depth=1 https://github.com/llvm/llvm-project.git
fi

cd llvm-project

# ensure we build with clang to use the plugin
export CC=clang
export CXX=clang++

mkdir -p build
cd build

cmake -S ../llvm  -G Ninja -DLLVM_ENABLE_PROJECTS="clang" -DLLVM_ENABLE_PLUGINS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=. -DCMAKE_C_FLAGS="-fpass-plugin=$EFACTS_LIB" -DCMAKE_CXX_FLAGS="-fpass-plugin=$EFACTS_LIB" -DLLVM_BUILD_LLVM_DYLIB=ON -DLLVM_USE_LINKER=lld -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_PARALLEL_LINK_JOBS=2 -DLLVM_PARALLEL_COMPILE_JOBS=2

ninja
ninja install

cd ..

# Ensure we extract new facts
if [ -d "llvm_facts" ]; then
    rm -rf llvm_facts 
fi
mkdir llvm_facts

# Extract the embedded info from the llvm opt binary

# Commented out right now since this generates approximately 120GB of output
#python3 ../linker/AnalysisEngine_linkmap.py --in_bin=llvm-project/build/bin/opt --out_dir=llvm_facts

