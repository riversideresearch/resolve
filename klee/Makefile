.PHONY: all clean build

all: build

uclibc:
	cd klee-uclibc-160/ && ./configure --make-llvm-lib --with-cc clang-16 --with-llvm-config llvm-config-16 && make -j$(nproc)

build: uclibc
	cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DLLVM_DIR=/usr/lib/llvm-16 -DCMAKE_BUILD_TYPE=Release -DENABLE_SOLVER_STP=OFF -DENABLE_SOLVER_Z3=ON -DENABLE_POSIX_RUNTIME=ON -DKLEE_UCLIBC_PATH=klee-uclibc-160 -DENABLE_UNIT_TESTS=OFF -DENABLE_KLEE_ASSERTS=OFF -DKLEE_RUNTIME_BUILD_TYPE=Release && cd build && make -j$(nproc)

clean:
	cd klee-uclibc-160 && make clean
	rm -rf build
