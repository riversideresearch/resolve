all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build
	+$(MAKE) -C test/test_annotate_functions

clean:
	rm -rf build
