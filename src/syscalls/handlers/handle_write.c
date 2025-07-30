// src/syscalls/handlers/handle_write.c
#define _GNU_SOURCE
#include "handle_write.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include <stdio.h>

/**
 * Handles the entry of a write syscall.
 * Logs the syscall number, name, and arguments,
 *
 * @param pid The process ID of the syscall initiator.
 * @param e The syscall event containing metadata.
 * @param args The arguments of the write syscall.
 */
void handle_write_enter(pid_t pid __attribute__((unused)),
                        const struct syscall_event *e,
                        const struct write_args *args) {
    char argbuf[128] = {0};
    snprintf(argbuf, sizeof(argbuf), "%d, %p, %zu",
             args->fd,          // file descriptor
             (void *)args->buf, // buffer pointer
             args->count);      // count of bytes to write
    log_syscall(e->syscall_nr, e->enter.name, argbuf, /*retval=*/0);

    const char *path = fd_cache_get(args->fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the exit of a write syscall.
 * Logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall initiator.
 * @param e The syscall event containing metadata.
 */
void handle_write_exit(pid_t pid __attribute__((unused)),
                       const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "write");
}
