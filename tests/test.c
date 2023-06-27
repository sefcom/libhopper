#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fakelib.h"

int main(int argc, char** argv, char** envp)
{
    lib_state state;
    char buf[BUF_SIZE];

    libapi_init(&state, "=== Test State ===", BUF_SIZE);

    libapi_name(&state);
    printf("Libfake version: %d\n", libapi_version(&state));

    libapi_read(&state, "random contenets lalala\n");
    libapi_write(&state, buf);
    printf("Libfake writeout: %s", buf);

    libapi_close(&state);

    return EXIT_SUCCESS;
}