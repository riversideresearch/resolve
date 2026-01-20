
.PHONY: all build clangformat test

all: build test

build: src
	mkdir -p build
	cmake -S ./src -B ./build  && cd build && make -j4

clangformat: src
	cd build && make clangformat

test: build
	lit -v tests/regression

clean:
	rm -rf build
