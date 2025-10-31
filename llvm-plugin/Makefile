all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build

	@which llvm-lit >/dev/null 2&>1 || (echo " Error: llvm-lit not found in PATH" && exit 1)
	+$(MAKE) -C test/test_annotate_functions
	+$(MAKE) -C test/test_cveassert

clean:
	rm -rf build
