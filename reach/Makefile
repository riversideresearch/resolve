.PHONY: all clean build

all: build

build: src lib
	cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cd build && make -j$(nproc)

clean:
	rm -rf build

lint:
	cpplint --filter=-build/c++17,-legal/copyright,-whitespace/indent_namespace,-build/include_subdir,-build/namespaces,-whitespace/line_length --exclude=build --exclude=src/argparse.hpp --exclude=lib/json.hpp --recursive .
