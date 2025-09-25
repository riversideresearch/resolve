all: src build clangformat
	cd build && make -j4

build: src
	mkdir -p build
	cd build && cmake ../src

clangformat: src
	cd build && make clangformat

clean: build
	rm -rf build
