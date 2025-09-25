#include <stdlib.h>

extern int DEBUG_APP_CrashCmd(void*);
extern int DEBUG_APP_CrashCmdUnsafe(void*);

int main(void) {
    DEBUG_APP_CrashCmd(NULL);
    // DEBUG_APP_CrashCmdUnsafe(NULL);
}
