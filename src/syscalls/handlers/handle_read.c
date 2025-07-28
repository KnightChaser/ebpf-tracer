// src/syscalls/handlers/handle_read.c
#define _GNU_SOURCE
#include "../../syscalls/syscalls.h"
#include "../fd_cache.h"
#include "../read_common.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter of the read syscall.
 * This function prints the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_read_enter(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    struct read_args args;
    if (fetch_read_args(pid, e, &args) == 0) {

        printf("%-6ld %-16s(%d, %p, %zu)\n",
               e->syscall_nr,    // syscall number
               e->enter.name,    // syscall name
               args.fd,          // file descriptor
               (void *)args.buf, // buffer pointer
               args.count        // number of bytes to read
        );

        const char *path = fd_cache_get(args.fd);
        if (path) {
            printf(" => path: %s\n", path);
        }
    } else {
        // fallback to the default printer
        handle_sys_enter_default(pid, e);
    }
    fflush(stdout);
}

/**
 * Handles the exit of the read syscall.
 * This function prints the return value and, if applicable, the data read.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_read_exit(pid_t pid __attribute__((unused)),
                      const struct syscall_event *e) {
    long ret = e->exit.retval;
    printf(" = %ld (read)\n", ret);
}
