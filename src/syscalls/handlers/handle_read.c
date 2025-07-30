// src/syscalls/handlers/handle_read.c
#define _GNU_SOURCE
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
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

    char argbuf[64];
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %zu",
             args.fd,          // file descriptor
             (void *)args.buf, // buffer pointer
             args.count);      // count of bytes to read
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    const char *path = fd_cache_get(args.fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
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
    log_ret(ret, "read");
}
