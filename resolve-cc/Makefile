all: build

.PHONY: format check clean

build: src
	cmake -B build && cmake --build build/

format: src
	cmake --build build/ --target format

check: build
	cmake --build build/ --target check

clean:
	rm -rf build
