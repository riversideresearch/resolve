all: build

.PHONY: format test check clean

build: src
	cmake -B build && cmake --build build/

format: src
	cmake --build build/ --target format

check: build
	cmake --build build/ --target check

test: build
	lit -v tests/

clean:
	rm -rf build
