SHELL := /bin/bash
all: build

build: build-resolve build-libresolve
.PHONY: build build-resolve build-libresolve

build-resolve: 
	cmake -Bbuild -GNinja
	cmake --build build

build-libresolve: libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build --release 

test: test-libresolve test-resolve-cveassert
.PHONY: test test-libresolve test-resolve-cveassert

test-libresolve:
	cd libresolve && cargo test

test-resolve-cveassert: build-resolve
	cmake --build build --target test-CVEAssert

install: install-resolve
.PHONY: install install-resolve

install-resolve: build-resolve
	cmake --install install

clean: clean-resolve clean-libresolve
.PHONY: clean clean-resolve clean-libresolve

clean-resolve:
	rm -rf build/
	rm -rf install/

clean-libresolve:
	cd libresolve && cargo clean

install-deps:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
.PHONY: install-deps
