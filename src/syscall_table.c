// src/syscall_table.c
#include "syscall_table.h"
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
    for (size_t i = 0; i < MAX_SYSCALL_NR; i++) {
        enter_handlers[i] = handle_sys_enter_default;
        exit_handlers[i] = handle_sys_exit_default;
    }

    // Register specific syscall handlers
    REGISTER_SYSCALL_HANDLER(SYS_openat, handle_sys_enter_openat,
                             handle_sys_exit_openat);
}
