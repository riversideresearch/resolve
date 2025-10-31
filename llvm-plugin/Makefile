LIT:= $(shell command -v llvm-lit 2>/dev/null || command -v lit)

all: build test

build: src
	mkdir -p build
	cd build && cmake ../src && make -j4

clangformat: src
	cd build && make clangformat

test: build
	@if [ -z "$(LIT)" ]; then \
		echo "Error: lit or llvm-lit not found."; \
		exit 1; \
	fi 
	
	$(LIT) -v tests
	+$(MAKE) -C test/test_annotate_functions
	+$(MAKE) -C test/test_cveassert

clean:
	rm -rf build
