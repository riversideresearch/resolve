LIT:= $(shell command -v llvm-lit 2>/dev/null || command -v lit)

all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build
	$(LIT) -v tests
	+$(MAKE) -C test/test_annotate_functions
	+$(MAKE) -C test/test_cveassert

clean:
	rm -rf build
