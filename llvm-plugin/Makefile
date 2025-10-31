all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build

	LIT:= $(shell command -v lit)
	$(LIT) -v tests
	+$(MAKE) -C test/test_annotate_functions
	+$(MAKE) -C test/test_cveassert

clean:
	rm -rf build
