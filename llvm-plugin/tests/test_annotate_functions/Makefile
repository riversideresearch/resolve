# Making modifications to Makefile for testing
# NOTE: compiler pass works on -O0 has difficulty with higher optimization levels
SRCS=$(wildcard *.c)
EXES=$(SRCS:.c=)
RUNTIME_LIB=../../../libresolve/target/debug
BUILD=../../build

bitcode: $(SRCS:.c=.ll) $(SRCS:.c=.ll.mem)

executables: $(SRCS:.c=.o) $(EXES)

all: bitcode executables

%.ll: %.c
	clang -S -O1 -emit-llvm $< -o $@

%.ll.mem: %.c
	clang -S -O1 -fpass-plugin=$(BUILD)/libAnnotateFunctions.so -fpass-plugin=$(BUILD)/libObjHook.so -emit-llvm $< -o $@

%.o: %.c
	clang -c -O1 -fpass-plugin=$(BUILD)/libAnnotateFunctions.so -fpass-plugin=$(BUILD)/libDlsymHook.so $< -o $@

%: %.o
	clang $< -L$(RUNTIME_LIB) -lresolve -Wl,-rpath=$(RUNTIME_LIB) -o $@

.PHONY: clean
clean:
	rm -f $(SRCS:.c=.ll) $(SRCS:.c=.ll.mem) $(SRCS:.c=.o) $(EXES)
