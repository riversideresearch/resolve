# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.

SHELL := /bin/bash
all: build

ifeq ($(origin BUILD_DIR),command line)
RESOLVE_CMAKE_BUILD_DIR ?= $(BUILD_DIR)
else ifeq ($(RESOLVE_BUILD_KLEE),ON)
RESOLVE_CMAKE_BUILD_DIR ?= build-with-klee
else
RESOLVE_CMAKE_BUILD_DIR ?= build
endif
RESOLVE_BUILD_KLEE ?= OFF
CMAKE_ARGS := -GNinja -DRESOLVE_BUILD_KLEE=$(RESOLVE_BUILD_KLEE)

RELEASE_BUILD_DIR ?= build-release
RELEASE_STAGE_DIR ?= dist/resolve-release-root
RELEASE_TARBALL ?= dist/resolve-linux-x86_64.tar.gz
RELEASE_INSTALL_PREFIX ?= /opt/resolve
RELEASE_PYTHON_VERSION ?= 3.12

.PHONY: build build-with-klee build-release build-release-with-klee check check-with-klee test test-with-klee install install-with-klee install-local release clean
configure: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS)

build: configure-default
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR)

build-with-klee:
	$(MAKE) build RESOLVE_BUILD_KLEE=ON

configure-default: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS) -DCMAKE_BUILD_TYPE=

build-release: configure-release
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR)

build-release-with-klee:
	$(MAKE) build-release RESOLVE_BUILD_KLEE=ON

configure-release: 
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Release

build-debug: configure-debug
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR)

configure-debug:
	cmake -B$(RESOLVE_CMAKE_BUILD_DIR) $(CMAKE_ARGS) -DCMAKE_BUILD_TYPE=Debug

build-debug-with-klee:
	$(MAKE) build-debug RESOLVE_BUILD_KLEE=ON

check: configure
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR) --target check

check-with-klee:
	$(MAKE) check RESOLVE_BUILD_KLEE=ON

test: configure
	cmake --build $(RESOLVE_CMAKE_BUILD_DIR) --target test-CVEAssert test-libresolve

test-with-klee:
	$(MAKE) test RESOLVE_BUILD_KLEE=ON

install: configure
	cmake --install $(RESOLVE_CMAKE_BUILD_DIR)

install-with-klee:
	$(MAKE) install RESOLVE_BUILD_KLEE=ON

install-local: configure
	cmake --install $(RESOLVE_CMAKE_BUILD_DIR) --prefix install

release:
	cmake -B$(RELEASE_BUILD_DIR) -GNinja -DRESOLVE_BUILD_KLEE=OFF -DRESOLVE_BUNDLE_PYTHON=ON -DRESOLVE_PYTHON_VERSION=$(RELEASE_PYTHON_VERSION) -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$(RELEASE_INSTALL_PREFIX) -DCMAKE_INSTALL_RPATH='$$ORIGIN;$$ORIGIN/../lib'
	cmake --build $(RELEASE_BUILD_DIR)
	./scripts/package-release.sh $(RELEASE_BUILD_DIR) $(RELEASE_STAGE_DIR) $(RELEASE_TARBALL) $(RELEASE_INSTALL_PREFIX)

clean:
	rm -rf build/ build-with-klee/

.PHONY: install-deps
install-deps:
	chmod u+x ./scripts/install-deps-ci.sh
	./scripts/install-deps-ci.sh
