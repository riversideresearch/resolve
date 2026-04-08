# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

SHELL := /bin/bash
all: build

.PHONY: build check test install clean
configure: 
	cmake -Bbuild -GNinja

build: configure-default
	cmake --build build

configure-default: 
	cmake -Bbuild -GNinja -DCMAKE_BUILD_TYPE=

build-release: configure-release
	cmake --build build

configure-release: 
	cmake -Bbuild -GNinja -DCMAKE_BUILD_TYPE=Release

check: configure
	cmake --build build --target check

test: configure
	cmake --build build --target test-CVEAssert test-libresolve

install: configure
	cmake --install build

install-local: configure
	cmake --install build --prefix install

clean:
	rm -rf build/

.PHONY: install-deps
install-deps:
	chmod u+x ./scripts/install-deps.sh
	./scripts/install-deps.sh
