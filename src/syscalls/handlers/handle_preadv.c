// src/syscalls/handlers/handle_preadv.c
#define _GNU_SOURCE
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include "../read_common.h"
#include <inttypes.h>
#include <stdio.h>

/**
 * Handles the enter of the preadv syscall.
 * This function logs the syscall arguments and retrieves the file path
 * associated with the file descriptor.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_preadv_enter(pid_t pid, const struct syscall_event *e) {
    struct read_args args;
    if (fetch_read_args(pid, e, &args) != 0) {
        handle_sys_enter_default(pid, e);
        return;
    }

    char argbuf[96];
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %d, %" PRIu64,
             args.fd,                  // file descriptor
             (void *)e->enter.args[1], // pointer to iovec array
             args.iovcnt,              // number of iovecs
             args.offset);             // offset in the file

    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    const char *path = fd_cache_get(args.fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the exit of the preadv syscall.
 * This function logs the return value of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_preadv_exit(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "read");
}
