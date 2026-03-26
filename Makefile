SHELL := /bin/bash
all: build

.PHONY: build check test install clean
build: configure
	cmake --build build

configure: 
	cmake -Bbuild -GNinja

check: configure
	cmake --build build --target check

test: configure
	cmake --build build --target test-CVEAssert test-libresolve

install: build
	cmake --install build

install-local: build
	cmake --install build --prefix install

clean:
	rm -rf build/

.PHONY: install-deps
install-deps:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
