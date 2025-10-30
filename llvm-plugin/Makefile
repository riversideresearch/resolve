all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build
	lit -v tests
	+$(MAKE) -C test/test_annotate_functions
	+$(MAKE) -C test/test_cveassert

clean:
	rm -rf build
