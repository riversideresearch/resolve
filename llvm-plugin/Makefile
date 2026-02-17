all: build test

.PHONY: clangformat test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build

clean:
	rm -rf build
