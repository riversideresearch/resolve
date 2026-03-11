// Test that the remediation is successful 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_loop_oob.json %clang -S -emit-llvm \
// RUN: -fpass-plugin=%plugin \
// RUN: %s -o - | %FileCheck %s 
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_loop_oob.json %clang -O0 -g -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; test $? -eq 3

// Test that the remediation is successful with optimizations
// RUN: RESOLVE_LABEL_CVE=vulnerabilities/stack_loop_oob.json %clang -O3 -fpass-plugin=%plugin \ 
// RUN: -L%rlib -lresolve -Wl,-rpath=%rlib %s -o %t.exe
// RUN: %t.exe; EXIT_CODE=$?; \
// RUN: echo Remediated exit: $EXIT_CODE; test $EXIT_CODE -eq 3

void vuln(char *buf) {
   for (int i = 0; i < 17; ++i) {
      buf[i] = 0x69;
   }
}

int main() {
   char tmp[8] = {0, 1, 2, 3, 4, 5, 6, 7};
   vuln(tmp);
   return 0;
}