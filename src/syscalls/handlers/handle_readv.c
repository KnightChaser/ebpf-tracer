// src/syscalls/handlers/handle_readv.c
#define _GNU_SOURCE
#include "../../syscalls/syscalls.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include "../read_common.h"
#include <inttypes.h>
#include <unistd.h>

/**
 * Handles the enter of the readv syscall.
 * This function prints the arguments of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_readv_enter(pid_t pid, const struct syscall_event *e) {
    struct read_args args;
    if (fetch_read_args(pid, e, &args) != 0) {
        handle_sys_enter_default(pid, e);
        return;
    }

    char argbuf[64];
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %d", args.fd,
             (void *)e->enter.args[1], args.iovcnt);
    log_syscall(e->syscall_nr, e->enter.name, argbuf, 0);

    const char *path = fd_cache_get(args.fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the exit of the readv syscall.
 * This function prints the return value and, if applicable, the data read.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_readv_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    log_ret(e->exit.retval, "pread");
}
