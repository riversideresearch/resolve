all: build

build: build-llvm-plugin build-libresolve

build-llvm-plugin: llvm-plugin build-libresolve
	+$(MAKE) -C llvm-plugin

build-libresolve: libresolve
	cd libresolve && RUSTFLAGS="-D warnings" cargo build

test: test-llvm-plugin

test-llvm-plugin:
	+$(MAKE) -C llvm-plugin test
