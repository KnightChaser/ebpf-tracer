// src/syscalls/handlers/handle_readv.c
#define _GNU_SOURCE
#include "handle_readv.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include "../read_common.h"
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter of the readv syscall.
 * This function prints the arguments of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 * @param args The arguments of the readv syscall.
 */
void handle_readv_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e,
                        const struct read_args *args) {
    char argbuf[64] = {0};
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %d",
             args->fd,                 // file descriptor
             (void *)e->enter.args[1], // buffer pointer
             args->iovcnt              // count of iovecs
    );
    log_syscall(e->syscall_nr, e->enter.name, argbuf, 0);

    const char *path = fd_cache_get(args->fd);
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
