// src/syscalls/handlers/handle_pread64.c
#define _GNU_SOURCE
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include "../read_common.h"
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

/**
 * Handles the enter of the pread64 syscall.
 * This function prints the arguments of the syscall.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the arguments.
 */
void handle_pread64_enter(pid_t pid __attribute__((unused)),
                          const struct syscall_event *e) {
    struct read_args args;

    char argbuf[128];
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %zu, %" PRIu64,
             args.fd,                // file descriptor
             (void *)args.buf,       // buffer pointer
             args.count,             // count of bytes to read
             (uint64_t)args.offset); // offset in bytes
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    const char *path = fd_cache_get(args.fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the exit of the pread64 syscall.
 * This function prints the return value and, if applicable, the data read.
 *
 * @param pid The process ID.
 * @param e The syscall event containing the return value.
 */
void handle_pread64_exit(pid_t pid __attribute__((unused)),
                         const struct syscall_event *e) {
    log_ret(e->exit.retval, "pread");
}
