#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "fakelib.h"

#define DEBUGx

/* Partially reference: https://stackoverflow.com/a/7776146 */
void hexdump_state(lib_state *state)
{
    // Silently ignore silly per-line values.
    int per_line = 16;

    int i;
    unsigned char buff[per_line + 1];
    const unsigned char * pc = (const unsigned char *)state;

    printf ("state name: %s\n", state->name);

    // Process every byte in the data.
    for (i = 0; i < sizeof(lib_state); i++) {
        // Multiple of perLine means new or first line (with line offset).
        if ((i % per_line) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.
            if (i != 0) printf ("  %s\n", buff);
            // Output the offset of current line.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % per_line] = '.';
        else
            buff[i % per_line] = pc[i];

        buff[(i % per_line) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.
    while ((i % per_line) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII buffer.
    printf ("  %s\n", buff);
}

int state_checker(lib_state *state)
{
    if (state->checker != VALID_STATE)
    {
        printf("ERROR in state checker: %d!\n", state->checker);
        return -1;
    }
    return 0;
}

int libapi_init(lib_state *state, char *name, int size)
{
    state->checker = VALID_STATE;
    state->size = size;
    state->version = VERSION;
    state->name = name;
    memset(state->buf, 0, BUF_SIZE);

    return 0;
}

int libapi_version(lib_state *state)
{
    #ifdef DEBUG
    hexdump_state(state);
    #endif

    return state->version;
}

int libapi_name(lib_state *state)
{
    #ifdef DEBUG
    hexdump_state(state);
    #endif

    printf ("state name: %s\n", state->name);
    return 0;
}

int libapi_read(lib_state *state, char *buf)
{
    #ifdef DEBUG
    hexdump_state(state);
    #endif

    if (state_checker(state) < 0)
        return -1;

    strncpy(state->buf, buf, state->size);
    return 0;
}

int libapi_write(lib_state *state, char *buf)
{
    #ifdef DEBUG
    hexdump_state(state);
    #endif

    if (state_checker(state) < 0)
        return -1;
    
    strncpy(buf, state->buf, state->size);
    return 0;
}

int libapi_close(lib_state *state)
{
    #ifdef DEBUG
    hexdump_state(state);
    #endif

    state->checker = 0;
    return 0;
}
