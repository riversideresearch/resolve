RUNTIME_LIB=../../../libresolve/target/debug

all: oob
.PHONY: all

CVE_ASSERT_SO=../../../build/libCVEAssert.so

memcpy_oob: memcpy_oob.c $(CVE_ASSERT_SO) vulnerabilities/memcpy_oob_vuln.json
	RESOLVE_LABEL_CVE=vulnerabilities/memcpy_oob_vuln.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S memcpy_oob.c


oob: oob.c $(CVE_ASSERT_SO) vulnerabilities/vulns.json
	RESOLVE_LABEL_CVE=vulnerabilities/vulns.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S oob.c
#	RESOLVE_LABEL_CVE=vulns.json clang $(CFLAGS) -L$(RUNTIME_LIB) -lresolve -Wl,-rpath=$(RUNTIME_LIB) -fpass-plugin=$(CVE_ASSERT_SO) oob.c -o oob

malloc_example: malloc_example.c $(CVE_ASSERT_SO) vulnerabilities/malloc_vulns.json
	RESOLVE_LABEL_CVE=vulnerabilities/malloc_vulns.json clang $(CFLAGS) -fpass-plugin=../../build/libObjHook.so -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S malloc_example.c
	RESOLVE_LABEL_CVE=vulnerabilities/malloc_vulns.json clang $(CFLAGS) -L$(RUNTIME_LIB) -lresolve -Wl,-rpath=$(RUNTIME_LIB) -fpass-plugin=../../build/libObjHook.so -fpass-plugin=$(CVE_ASSERT_SO) malloc_example.c -o malloc_example

multvars: multvars.c $(CVE_ASSERT_SO) vulnerabilities/multvars.json
	RESOLVE_LABEL_CVE=vulnerabilities/multvars.json clang $(CFLAGS) -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S multvars.c

oob_multvars: oob_multvars.c $(CVE_ASSERT_SO) vulnerabilities/oob_multvars.json
	RESOLVE_LABEL_CVE=vulnerabilities/oob_multvars.json clang -g -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S oob_multvars.c
#	RESOLVE_LABEL_CVE=vulnerabilities/oob_multvars clang $(CFLAGS) -L$(RUNTIME_LIB) -lresolve -Wl,-rpath=$(RUNTIME_LIB) -fpass-plugin=$(CVE_ASSERT_SO) oob.c -o oob

funct_multvars: funct_multvars.c $(CVE_ASSERT_SO) vulnerabilities/funct_with_multvars.json
	RESOLVE_LABEL_CVE=vulnerabilities/funct_with_multvars.json clang -g -fpass-plugin=$(CVE_ASSERT_SO) -emit-llvm -S funct_multvars.c

clean:
	rm -f oob oob.ll multvars.ll oob_multvars.ll funct_multvars.ll

