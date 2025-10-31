#include <stdlib.h>
#include <stdint.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/
/*                                                                            */
/* DEBUG Crash command                                                         */
/*                                                                            */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/
uint8_t DEBUG_APP_Data = 0;

void DEBUG_APP_CrashCmd(const void *Msg)
{
    DEBUG_APP_Data++;

    uint8_t *crash = Msg;
    crash[5] = 'a';
}

int main(void) {
    DEBUG_APP_CrashCmd(NULL);
}
