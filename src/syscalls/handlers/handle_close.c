// src/syscalls/handlers/handle_close.c
#define _GNU_SOURCE
#include "../../controller.h"
#include "../fd_cache.h"
#include "../syscalls.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    int fd = (int)e->enter.args[0];
    printf("%-6ld %-16s(%d)", e->syscall_nr, e->enter.name, fd);
    const char *path = fd_cache_get(fd);
    if (path) {
        printf("\n => path: %s\n", path);
    }
}

/**
 * Handles the exit event of the close syscall.
 *
 * @param pid The process ID of the syscall event.
 * @param e The syscall event structure containing syscall information.
 */
void handle_close_exit(pid_t pid, const struct syscall_event *e) {
    handle_sys_exit_default(pid, e);
}
