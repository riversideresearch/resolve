
all: debug debug_llvm stack_free debug_broken
.PHONY: all

CVE_ASSERT_SO=../../build/libCVEAssert.so

debug: debug.c vulns.json $(CVE_ASSERT_SO)
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S debug.c
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) debug.c -o debug

debug_broken: debug_broken.c vulns.json $(CVE_ASSERT_SO)
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S debug_broken.c
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) debug_broken.c -o debug_broken

# Version that links together llvm debug output from pass 
debug_llvm: debug_llvm.c vulns.json DEBUG_APP_CrashCmd.ll
	clang $(CFLAGS) debug_llvm.c DEBUG_APP_CrashCmd.ll -o debug_llvm

stack_free: stack_free.c vulns.json $(CVE_ASSERT_SO)
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S stack_free.c
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) stack_free.c -o stack_free

div_zero: div_zero.c vulns.json $(CVE_ASSERT_SO)
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S div_zero.c
	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) div_zero.c -o div_zero

div_zero_function: div_zero_function_ex.c div_vulns.json $(CVE_ASSERT_SO)
	clang -S -emit-llvm div_zero_function_ex.c -o div_zero_function_ex.ll.test
	RESOLVE_LABEL_CVE=div_vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S div_zero_function_ex.c

clean:
	rm -f stack_free debug_llvm debug debug_broken
