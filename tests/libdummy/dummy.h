#ifndef DUMMY_H
#define DUMMY_H

/*
 * This header file used to simulate the user library's LIBRARY.h file. It will
 * try best to contain functions similar to function calls provide by a library.
 * Including but not constrained to:
 * - Initialize internal state
 * - Destroy/Close internal state
 * - Operate on internel state
 * - Error handling on corrupted internal state
 *
 * Naming:
 * All the function apis will start with `libapi_` and its internal state is 
 * `struct lib_state_st`, `typedef lib_state_st lib_state` with parameter name
 * to be `lib_state *state`
 */

#define VALID_STATE 0x11
#define VERSION 0x99
#define BUF_SIZE 0x50

struct lib_state_st
{
    int checker;
    char *name;
    int size;
    char buf[BUF_SIZE];
    int version;
    int lottery_idx;
    void (*secret)(void);
};

typedef struct lib_state_st lib_state;

/* Helper functions */
void hexdump_state(lib_state *state);
int state_checker(lib_state *state);
void secret_func(void);

/* Library api functions */
int libapi_init(lib_state *state, char *name, int size);
int libapi_version(lib_state *state);
int libapi_name(lib_state *state);
int libapi_read(lib_state *state, char *buf);
int libapi_write(lib_state *state, char *buf);
int libapi_lotto(lib_state *state);
int libapi_exec(lib_state *state);
int libapi_close(lib_state *state);

#endif /* DUMMY_H */