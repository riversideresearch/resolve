SHELL := /bin/bash
all: build

build: build-resolve-facts build-llvm-plugin build-resolve-cveassert build-libresolve build-reach build-klee

build-resolve-facts: resolve-facts
	+$(MAKE) -C resolve-facts

build-llvm-plugin: llvm-plugin build-libresolve build-resolve-facts
	+$(MAKE) -C llvm-plugin

build-resolve-cveassert: resolve-cveassert build-libresolve
	+$(MAKE) -C resolve-cveassert

build-libresolve: libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build --release 

test: test-llvm-plugin test-libresolve

test-libresolve:
	cd libresolve && cargo test

test-llvm-plugin:
	+$(MAKE) -C llvm-plugin test

build-reach: reach build-resolve-facts
	+$(MAKE) -C reach

build-klee: klee build-reach build-resolve-facts
	+$(MAKE) -C klee

clean: clean-resolve-facts clean-llvm-plugin clean-resolve-cveassert clean-libresolve clean-reach clean-klee

clean-resolve-facts:
	cd resolve-facts && make clean

clean-llvm-plugin:
	cd llvm-plugin && make clean

clean-resolve-cveassert:
	+$(MAKE) -C resolve-cveassert clean

clean-libresolve:
	cd libresolve && cargo clean

clean-reach:
	cd reach && make clean

clean-klee:
	cd klee && make clean

install-packages:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
