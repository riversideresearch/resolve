SHELL := /bin/bash
all: build

build: build-resolve-facts build-resolve-cc build-resolve-cveassert build-libresolve build-reach build-klee

build-resolve-facts: resolve-facts
	+$(MAKE) -C resolve-facts

build-resolve-cc: resolve-cc build-libresolve build-resolve-facts
	+$(MAKE) -C resolve-cc

build-resolve-cveassert: resolve-cveassert build-libresolve
	+$(MAKE) -C resolve-cveassert

build-libresolve: libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build --release 

test: test-resolve-cc test-libresolve

test-libresolve:
	cd libresolve && cargo test

test-resolve-cc:
	+$(MAKE) -C resolve-cc test

build-reach: reach build-resolve-facts
	+$(MAKE) -C reach

build-klee: klee build-reach build-resolve-facts
# 	+$(MAKE) -C klee

clean: clean-resolve-facts clean-resolve-cc clean-resolve-cveassert clean-libresolve clean-reach clean-klee

clean-resolve-facts:
	cd resolve-facts && make clean

clean-resolve-cc:
	cd resolve-cc && make clean

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
