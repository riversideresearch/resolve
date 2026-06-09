# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

SHELL := /bin/bash
all: build

ifeq ($(origin BUILD_DIR),command line)
RESOLVE_CMAKE_BUILD_DIR ?= $(BUILD_DIR)
else
RESOLVE_CMAKE_BUILD_DIR ?= build
endif
RESOLVE_BUILD_KLEE ?= OFF
CMAKE_ARGS := -GNinja -DRESOLVE_BUILD_KLEE=$(RESOLVE_BUILD_KLEE)

.PHONY: build build-klee build-release build-release-klee check check-klee test test-klee install install-klee install-local clean
configure: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS)

build: configure-default
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR)

build-klee:
	$(MAKE) build RESOLVE_CMAKE_BUILD_DIR=build-klee RESOLVE_BUILD_KLEE=ON

configure-default: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS) -DCMAKE_BUILD_TYPE=

build-release: configure-release
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR)

build-release-klee:
	$(MAKE) build-release RESOLVE_CMAKE_BUILD_DIR=build-klee RESOLVE_BUILD_KLEE=ON

configure-release: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release

check: configure
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR) --target check

check-klee:
	$(MAKE) check RESOLVE_CMAKE_BUILD_DIR=build-klee RESOLVE_BUILD_KLEE=ON

test: configure
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR) --target test-CVEAssert test-libresolve

test-klee:
	$(MAKE) test RESOLVE_CMAKE_BUILD_DIR=build-klee RESOLVE_BUILD_KLEE=ON

install: configure
	cmake --install $(RESOLVE_CMAKE_BUILD_DIR)

install-klee:
	$(MAKE) install RESOLVE_CMAKE_BUILD_DIR=build-klee RESOLVE_BUILD_KLEE=ON

install-local: configure
	cmake --install $(RESOLVE_CMAKE_BUILD_DIR) --prefix install

clean:
	rm -rf build/ build-klee/

.PHONY: install-deps
install-deps:
	chmod u+x ./scripts/install-deps-ci.sh
	./scripts/install-deps-ci.sh
