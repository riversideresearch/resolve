all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build
	lit -v tests/regression
	+$(MAKE) -C tests/test_annotate_functions
clean:
	rm -rf build
