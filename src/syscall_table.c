// src/syscall_table.c
#include "syscall_table.h"
#include "syscalls/open_common.h"
#include "syscalls/syscalls.h"
#include <stddef.h>

syscall_handler_t enter_handlers[MAX_SYSCALL_NR];
syscall_handler_t exit_handlers[MAX_SYSCALL_NR];

/**
 * Initializes the syscall handlers to default handlers.
 * This function sets up the enter and exit handlers for syscalls.
 * It can be extended to register specific syscall handlers.
 */
void syscall_table_init(void) {
    // NOTE: Initialize all syscall handlers to default handlers
    for (size_t i = 0; i < MAX_SYSCALL_NR; i++) {
        enter_handlers[i] = handle_sys_enter_default;
        exit_handlers[i] = handle_sys_exit_default;
    }

    // NOTE: Register specific syscall handlers

    // open/openat/openat2 syscalls
    REGISTER_SYSCALL_HANDLER(SYS_open, open_enter_dispatch, open_exit_dispatch);
    REGISTER_SYSCALL_HANDLER(SYS_openat, open_enter_dispatch,
                             open_exit_dispatch);
#ifdef SYS_openat2
#if SYS_openat2 < SYSCALL_TABLE_SIZE
    REGISTER_SYSCALL_HANDLER(SYS_openat2, open_enter_dispatch,
                             open_exit_dispatch);
#endif
#endif

    // close(2)
    REGISTER_SYSCALL_HANDLER(SYS_close, handle_close_enter, handle_close_exit);
}
