SHELL := /bin/bash
all: build

build: build-resolve-facts build-llvm-plugin build-libresolve build-reach build-klee

lib-folder:
	mkdir -p comp_libs

build-resolve-facts: resolve-facts
	+$(MAKE) -C resolve-facts

build-llvm-plugin: lib-folder llvm-plugin build-libresolve build-resolve-facts
	+$(MAKE) -C llvm-plugin && cp llvm-plugin/build/lib*.so comp_libs/

build-libresolve: lib-folder libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build --release && cp target/release/libresolve.so ../comp_libs

test: test-llvm-plugin test-libresolve

test-libresolve:
	cd libresolve && cargo test

test-llvm-plugin:
	+$(MAKE) -C llvm-plugin test

build-reach: reach build-resolve-facts
	+$(MAKE) -C reach

build-klee: klee build-reach build-resolve-facts
	+$(MAKE) -C klee

clean: clean-resolve-facts clean-llvm-plugin clean-libresolve clean-reach clean-klee

clean-resolve-facts:
	cd resolve-facts && make clean

clean-llvm-plugin:
	cd llvm-plugin && make clean

clean-libresolve:
	cd libresolve && cargo clean

clean-reach:
	cd reach && make clean

clean-klee:
	cd klee && make clean

install-packages:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
