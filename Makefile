SHELL := /bin/bash
all: build

build: build-llvm-plugin build-libresolve build-reach

build-llvm-plugin: llvm-plugin build-libresolve
	+$(MAKE) -C llvm-plugin

build-libresolve: libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build

test: test-llvm-plugin

test-llvm-plugin:
	+$(MAKE) -C llvm-plugin test

build-reach: reach
	+$(MAKE) -C reach

clean: clean-llvm-plugin clean-libresolve clean-reach

clean-llvm-plugin:
	cd llvm-plugin && make clean

clean-libresolve:
	cd libresolve && cargo clean

clean-reach:
	cd reach && make clean

install-packages:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh