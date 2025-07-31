// src/syscalls/handlers/handle_pwrite64.c
#define _GNU_SOURCE
#include "handle_pwrite64.h"
#include "../../utils/logger.h"
#include "../fd_cache.h"
#include <inttypes.h>
#include <stdio.h>

/**
 * Handles the entry of a pwrite64 syscall.
 * Logs the syscall number, name, and arguments,
 * including file descriptor, buffer pointer, count of bytes to write,
 * and offset in the file.
 *
 * @param pid The process ID of the syscall initiator.
 * @param e The syscall event containing metadata.
 * @param args The arguments of the pwrite64 syscall.
 */
void handle_pwrite64_enter(pid_t pid __attribute__((unused)),
                           const struct syscall_event *e,
                           const struct write_args *args) {
    char argubf[128] = {0};
    snprintf(argubf, sizeof(argubf), "%d, %p, %zu, %" PRIu64,
             args->fd,          // file descriptor
             (void *)args->buf, // buffer pointer
             args->count,       // count of bytes to write
             args->offset);     // offset in the file
    log_syscall(e->syscall_nr, e->enter.name, argubf, /*retval=*/0);

    const char *path = fd_cache_get(args->fd);
    if (path) {
        log_kv("path", "%s", path);
    } else {
        log_kv("path", "<unknown>");
    }
}

/**
 * Handles the exit of a pwrite64 syscall.
 * Logs the return value of the syscall.
 *
 * @param pid The process ID of the syscall initiator.
 * @param e The syscall event containing metadata.
 */
void handle_pwrite64_exit(pid_t pid __attribute__((unused)),
                          const struct syscall_event *e) {
    long ret = e->exit.retval;
    log_ret(ret, "pwrite64");
}
