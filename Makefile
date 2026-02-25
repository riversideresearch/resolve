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
	cmake --build build --target test-CVEAssert

install: build
	cmake --install install

clean:
	rm -rf build/

.PHONY: install-deps
install-deps:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
